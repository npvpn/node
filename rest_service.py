import asyncio
import json
import time
from contextlib import asynccontextmanager, contextmanager
from functools import partial
from threading import Lock
from uuid import UUID, uuid4

from fastapi import (APIRouter, Body, FastAPI, HTTPException, Request,
                     WebSocket, status)
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocketDisconnect

from config import HAPROXY_PILOT_POLICY, HAPROXY_PILOT_STATE_DIR, XRAY_ASSETS_PATH, XRAY_EXECUTABLE_PATH
from haproxy_pilot import Conflict, Pilot, Rejected
from haproxy_runtime import Command, Model
from logger import logger
from xray import XRayConfig, XRayCore

@asynccontextmanager
async def lifespan(app):
    service.enable_pilot()
    yield


app = FastAPI(lifespan=lifespan)


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError):
    details = {}
    for error in exc.errors():
        details[error["loc"][-1]] = error.get("msg")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=jsonable_encoder({"detail": details}),
    )


class PilotSession(Model):
    session_id: UUID


class PilotCommand(Command, PilotSession):
    pass


class PilotResult(PilotSession):
    operation_id: UUID


class Service(object):
    def __init__(self):
        self.router = APIRouter()

        self.connected = False
        self.client_ip = None
        self.session_id = None
        self.core = XRayCore(
            executable_path=XRAY_EXECUTABLE_PATH,
            assets_path=XRAY_ASSETS_PATH
        )
        self.core_version = self.core.get_version()
        self.config = None
        self.pilot = None
        self._session_lock = Lock()

        self.router.add_api_route("/", self.base, methods=["POST"])
        self.router.add_api_route("/ping", self.ping, methods=["POST"])
        self.router.add_api_route("/connect", self.connect, methods=["POST"])
        self.router.add_api_route("/disconnect", self.disconnect, methods=["POST"])
        self.router.add_api_route("/start", self.start, methods=["POST"])
        self.router.add_api_route("/stop", self.stop, methods=["POST"])
        self.router.add_api_route("/restart", self.restart, methods=["POST"])

        self.router.add_api_route("/haproxy-pilot/status", self.pilot_status, methods=["POST"])
        self.router.add_api_route("/haproxy-pilot/validate", self.pilot_validate, methods=["POST"])
        self.router.add_api_route("/haproxy-pilot/apply", self.pilot_apply, methods=["POST"])
        self.router.add_api_route("/haproxy-pilot/result", self.pilot_result, methods=["POST"])

        self.router.add_websocket_route("/logs", self.logs)

    def match_session_id(self, session_id: UUID):
        if session_id != self.session_id:
            raise HTTPException(
                status_code=403,
                detail="Session ID mismatch."
            )
        return True

    def response(self, **kwargs):
        return {
            "connected": self.connected,
            "started": self.core.started,
            "core_version": self.core_version,
            **kwargs
        }

    def base(self):
        return self.response(**({"capabilities": {"haproxy_pilot": 1}} if self.pilot else {}))

    def enable_pilot(self):
        if HAPROXY_PILOT_POLICY:
            try:
                self.pilot = Pilot(HAPROXY_PILOT_POLICY, HAPROXY_PILOT_STATE_DIR)
            except Exception:
                logger.exception("Could not initialize HAProxy pilot")

    def _session_pilot(self, session):
        self.match_session_id(session.session_id)
        if self.pilot is None:
            raise HTTPException(404, "HAProxy pilot is disabled")
        return self.pilot

    @contextmanager
    def _pilot_admission(self, session_id):
        with self._session_lock:
            self.match_session_id(session_id)
            yield

    def pilot_status(self, request: PilotSession):
        return self._session_pilot(request).status(partial(self._pilot_admission, request.session_id))

    def _pilot_command(self, request, validate):
        pilot = self._session_pilot(request)
        command = request.model_dump(exclude={"session_id"})
        try:
            method = pilot.validate if validate else pilot.apply
            return method(command, partial(self._pilot_admission, request.session_id))
        except Conflict as error:
            raise HTTPException(409, str(error)) from error
        except Rejected as error:
            raise HTTPException(422, str(error)) from error

    def pilot_validate(self, request: PilotCommand):
        return self._pilot_command(request, validate=True)

    def pilot_apply(self, request: PilotCommand):
        return self._pilot_command(request, validate=False)

    def pilot_result(self, request: PilotResult):
        result = self._session_pilot(request).result(request.operation_id, partial(self._pilot_admission, request.session_id))
        if result is None:
            raise HTTPException(404, "Unknown operation")
        return result

    def connect(self, request: Request):
        with self._session_lock:
            self.session_id = uuid4()
            self.client_ip = request.client.host

        if self.connected:
            logger.warning(
                f'New connection from {self.client_ip}, Core control access was taken away from previous client.')
            if self.core.started:
                try:
                    self.core.stop()
                except RuntimeError:
                    pass

        self.connected = True
        logger.info(f'{self.client_ip} connected, Session ID = "{self.session_id}".')

        return self.response(
            session_id=self.session_id
        )

    def disconnect(self):
        if self.connected:
            logger.info(f'{self.client_ip} disconnected, Session ID = "{self.session_id}".')

        with self._session_lock:
            self.session_id = None
            self.client_ip = None
            self.connected = False

        if self.core.started:
            try:
                self.core.stop()
            except RuntimeError:
                pass

        return self.response()

    def ping(self, session_id: UUID = Body(embed=True)):
        self.match_session_id(session_id)
        return {}

    def start(self, session_id: UUID = Body(embed=True), config: str = Body(embed=True)):
        self.match_session_id(session_id)

        # Core уже запущен — возвращаем успех, избегая 503 и цепочки restart
        if self.core.started:
            return self.response()
        
        try:
            config = XRayConfig(config, self.client_ip)
        except json.decoder.JSONDecodeError as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "config": f'Failed to decode config: {exc}'
                }
            )

        with self.core.get_logs() as logs:
            try:
                self.core.start(config)

                start_time = time.time()
                end_time = start_time + 3
                last_log = ''
                while time.time() < end_time:
                    while logs:
                        log = logs.popleft()
                        if log:
                            last_log = log
                        if f'Xray {self.core_version} started' in log:
                            break
                    time.sleep(0.1)

            except Exception as exc:
                logger.error(f"Failed to start core: {exc}")
                raise HTTPException(
                    status_code=503,
                    detail=str(exc)
                )

        if not self.core.started:
            raise HTTPException(
                status_code=503,
                detail=last_log
            )

        return self.response()

    def stop(self, session_id: UUID = Body(embed=True)):
        self.match_session_id(session_id)

        try:
            self.core.stop()

        except RuntimeError:
            pass

        return self.response()

    def restart(self, session_id: UUID = Body(embed=True), config: str = Body(embed=True)):
        self.match_session_id(session_id)

        try:
            config = XRayConfig(config, self.client_ip)
        except json.decoder.JSONDecodeError as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "config": f'Failed to decode config: {exc}'
                }
            )

        try:
            with self.core.get_logs() as logs:
                self.core.restart(config)

                start_time = time.time()
                end_time = start_time + 3
                last_log = ''
                while time.time() < end_time:
                    while logs:
                        log = logs.popleft()
                        if log:
                            last_log = log
                        if f'Xray {self.core_version} started' in log:
                            break
                    time.sleep(0.1)

        except Exception as exc:
            logger.error(f"Failed to restart core: {exc}")
            raise HTTPException(
                status_code=503,
                detail=str(exc)
            )

        if not self.core.started:
            raise HTTPException(
                status_code=503,
                detail=last_log
            )

        return self.response()

    async def logs(self, websocket: WebSocket):
        session_id = websocket.query_params.get('session_id')
        interval = websocket.query_params.get('interval')

        try:
            session_id = UUID(session_id)
            if session_id != self.session_id:
                return await websocket.close(reason="Session ID mismatch.", code=4403)

        except ValueError:
            return await websocket.close(reason="session_id should be a valid UUID.", code=4400)

        if interval:
            try:
                interval = float(interval)

            except ValueError:
                return await websocket.close(reason="Invalid interval value.", code=4400)

            if interval > 10:
                return await websocket.close(reason="Interval must be more than 0 and at most 10 seconds.", code=4400)

        await websocket.accept()

        cache = ''
        last_sent_ts = 0
        with self.core.get_logs() as logs:
            while session_id == self.session_id:
                if interval and time.time() - last_sent_ts >= interval and cache:
                    try:
                        await websocket.send_text(cache)
                    except (WebSocketDisconnect, RuntimeError):
                        break
                    cache = ''
                    last_sent_ts = time.time()

                if not logs:
                    try:
                        await asyncio.wait_for(websocket.receive(), timeout=0.2)
                        continue
                    except asyncio.TimeoutError:
                        continue
                    except (WebSocketDisconnect, RuntimeError):
                        break

                log = logs.popleft()

                if interval:
                    cache += f'{log}\n'
                    continue

                try:
                    await websocket.send_text(log)
                except (WebSocketDisconnect, RuntimeError):
                    break

        await websocket.close()


service = Service()
app.include_router(service.router)
