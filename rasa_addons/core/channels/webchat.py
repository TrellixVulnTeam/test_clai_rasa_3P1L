import logging
import warnings
import uuid
import os
from sanic import Sanic, Blueprint, response
from sanic.request import Request
from sanic.response import HTTPResponse
from socketio import AsyncServer
from rasa.shared.utils.io import raise_warning
import re
from typing import Text, List, Dict, Any, Optional, Callable, Iterable, Awaitable

from rasa.core.channels.channel import UserMessage, InputChannel
from rasa.core.channels.socketio import SocketIOInput, SocketIOOutput, SocketBlueprint
from rasa_addons.core.channels.graphql import get_config_via_graphql
import requests
import math
import base64
import random
import json
from http import HTTPStatus
from rasa_sdk.events import UserUtteranceReverted, ActionReverted, FollowupAction, SlotSet
from rasa_sdk.executor import CollectingDispatcher

logger = logging.getLogger(__name__)


class WebchatOutput(SocketIOOutput):
    @classmethod
    def name(cls):
        return "webchat"

    def __init__(
        self, sio: AsyncServer, bot_message_evt: Text
    ) -> None:  # until SocketIOOutput implement comes out
        self.sio = sio
        self.bot_message_evt = bot_message_evt

    async def _send_message(self, socket_id: Text, response: Any) -> None:
        """Sends a message to the recipient using the bot event."""

        await self.sio.emit(self.bot_message_evt, response, room=socket_id)

    async def send_text_message(
        self, recipient_id: Text, text: Text, **kwargs: Any
    ) -> None:
        """Send a message through this channel."""

        message_parts = text.split("\n\n")
        for message_part in message_parts:
            await self._send_message(
                recipient_id,
                {"text": message_part, "metadata": kwargs.get("metadata", {})},
            )

    async def send_image_url(
        self, recipient_id: Text, image: Text, **kwargs: Any
    ) -> None:
        """Sends an image to the output"""

        message = {
            "attachment": {"type": "image", "payload": {"src": image}},
            "metadata": kwargs.get("metadata", {}),
        }
        await self._send_message(recipient_id, message)

    async def send_text_with_buttons(
        self,
        recipient_id: Text,
        text: Text,
        buttons: List[Dict[Text, Any]],
        **kwargs: Any,
    ) -> None:
        """Sends buttons to the output."""

        message = {
            "text": text,
            "buttons": buttons,
            "metadata": kwargs.get("metadata", {}),
        }

        await self._send_message(recipient_id, message)

    async def send_quick_replies(
        self,
        recipient_id: Text,
        text: Text,
        quick_replies: List[Dict[Text, Any]],
        **kwargs: Any,
    ) -> None:
        """Sends quick replies to the output."""

        message = {
            "text": text,
            "quick_replies": quick_replies,
            "metadata": kwargs.get("metadata", {}),
        }

        await self._send_message(recipient_id, message)

    async def send_elements(
        self, recipient_id: Text, elements: Iterable[Dict[Text, Any]], **kwargs: Any
    ) -> None:
        """Sends elements to the output."""

        message = {
            "attachment": {
                "type": "template",
                "payload": {"template_type": "generic", "elements": elements},
            },
            "metadata": kwargs.get("metadata", {}),
        }

        await self._send_message(recipient_id, message)

    async def send_custom_json(
        self, recipient_id: Text, json_message: Dict[Text, Any], **kwargs: Any
    ) -> None:
        """Sends custom json to the output"""

        message = {
            **json_message,
            "metadata": kwargs.get("metadata", {}),
        }
        await self._send_message(recipient_id, message)

    async def send_attachment(
        self, recipient_id: Text, attachment: Dict[Text, Any], **kwargs: Any
    ) -> None:
        """Sends an attachment to the user."""
        await self._send_message(
            recipient_id,
            {"attachment": attachment, "metadata": kwargs.get("metadata", {})},
        )


class WebchatInput(SocketIOInput):
    @classmethod
    def from_credentials(cls, credentials: Optional[Dict[Text, Any]]) -> InputChannel:
        return cls(
            credentials.get("user_message_evt", "user_uttered"),
            credentials.get("bot_message_evt", "bot_uttered"),
            credentials.get("namespace"),
            credentials.get("session_persistence", False),
            credentials.get("socketio_path", "/socket.io"),
            credentials.get("cors_allowed_origins", "*"),
            credentials.get("config"),
        )

    @classmethod
    def name(cls):
        return "webchat"

    def __init__(
        self,
        user_message_evt: Text = "user_uttered",
        bot_message_evt: Text = "bot_uttered",
        namespace: Optional[Text] = None,
        session_persistence: bool = False,
        socketio_path: Optional[Text] = "/socket.io",
        cors_allowed_origins="*",
        config=None,
    ):
        self.bot_message_evt = bot_message_evt
        self.session_persistence = session_persistence
        self.user_message_evt = user_message_evt
        self.namespace = namespace
        self.socketio_path = socketio_path
        self.cors_allowed_origins = cors_allowed_origins
        self.sio = None
        self.config = config

    def get_output_channel(self) -> Optional["OutputChannel"]:
        if self.sio is None:
            raise_warning(
                "SocketIO output channel cannot be recreated. "
                "This is expected behavior when using multiple Sanic "
                "workers or multiple Rasa Open Source instances. "
                "Please use a different channel for external events in these "
                "scenarios."
            )
            return
        return WebchatOutput(self.sio, self.bot_message_evt)

    def get_metadata(self, request: Request) -> Optional[Dict[Text, Any]]:
        return request.get("customData", {})

    def generateString(self,authToken):
        randomBase = 'Q2xhcml0eS0xNC40LUFybXN0cm9uZw=='
        posAuthToken = 12
        posLogin = 15
        if authToken!="":
            authLength = len(authToken)
            authList=list(authToken)  
            if authLength == 0:
                pos=posLogin
            else:
                pos1=authList[int(posAuthToken)]
                pos=int(pos1, 16) 
            seed = 'VGhlIHF1aWNrIGJyb3duIGZveA'
            lnth = len(seed)
            emptystr=''
            for i in range(0,lnth):
                emptystr = emptystr+seed[math.floor(random.uniform(0,1)* lnth)]
            encodedString = (emptystr[0:pos]+randomBase).encode("utf-8")
            encodebase64=base64.b64encode(encodedString)
            result= base64.b64encode(encodebase64)
            return result
        elif authToken=="":
            return "empty"
        else:
            return ""

    def getUserContext(self,data):
        if self.get_metadata(data).get('clarity'):
            logger.debug("metadata inside usercontext function")
            logger.debug(self.get_metadata(data))
            authtoken = self.get_metadata(data).get('clarity').get('authToken')
            pem_cty_sso = self.get_metadata(data).get('clarity').get('pem_cty_sso')
            apistring = self.generateString(authtoken)
            if apistring!="":
                headers = {
                    'authToken': authtoken,
                    'x-api-next-string': apistring
                }
                
                
                cookies = dict(sessionId=authtoken)
                
                if pem_cty_sso:
                    cookies['pem_cty_sso'] = pem_cty_sso
                    
                url = self.get_metadata(data).get('clarity').get('url')
                if url!="":
                    a = url.split("/")
                    host = a[0]+"//"+a[1]+a[2]
                    resturl=host+"/ppm/rest/v1/private/userContext"
                    response=""
                    try:
                        response = requests.request("GET", resturl, headers=headers, cookies=cookies)
                        response.raise_for_status()
                    except requests.exceptions.HTTPError as errh:
                        logger.debug( "An Http Error occurred:" )
                        logger.debug(repr(errh))
                    except requests.exceptions.ConnectionError as errc:
                        logger.debug( "An Error Connecting to the API occurred:" )
                        logger.debug(repr(errc))
                    except requests.exceptions.Timeout as errt:
                        logger.debug( "A Timeout Error occurred:" )
                        logger.debug(repr(errt))
                    except requests.exceptions.RequestException as err:
                        logger.debug( "An Unknown Error occurred" )
                        logger.debug(repr(err))
                    return response
                elif url=="":
                    return "empty"
                else:
                    return ""
            elif apistring=="empty":
                return "empty"
            else:
                return ""
        else:
            return ""

    def blueprint(
        self, on_new_message: Callable[[UserMessage], Awaitable[Any]]
    ) -> Blueprint:
        # Workaround so that socketio works with requests from other origins.
        # https://github.com/miguelgrinberg/python-socketio/issues/205#issuecomment-493769183
        sio = AsyncServer(
            async_mode="sanic", cors_allowed_origins=self.cors_allowed_origins
        )
        socketio_webhook = SocketBlueprint(
            sio, self.socketio_path, "socketio_webhook", __name__
        )

        # make sio object static to use in get_output_channel
        self.sio = sio

        @socketio_webhook.route("/", methods=["GET"])
        async def health(_: Request) -> HTTPResponse:
            return response.json({"status": "ok"})

        @sio.on("connect", namespace=self.namespace)
        async def connect(sid: Text, _) -> None:
            logger.debug(f"User {sid} connected to socketIO endpoint.")

        @sio.on("disconnect", namespace=self.namespace)
        async def disconnect(sid: Text) -> None:
            logger.debug(f"User {sid} disconnected from socketIO endpoint.")

        @sio.on("session_request", namespace=self.namespace)
        async def session_request(sid: Text, data: Optional[Dict]):
            props = {}
            if data is None:
                data = {}
            if "session_id" not in data or data["session_id"] is None:
                data["session_id"] = uuid.uuid4().hex
            if self.session_persistence:
                sio.enter_room(sid, data["session_id"])
            if self.config is not None:
                props = self.config
            else:
                config = await get_config_via_graphql(
                    os.environ.get("BF_URL"), os.environ.get("BF_PROJECT_ID")
                )
                if config and "credentials" in config:
                    credentials = config.get("credentials", {})
                    channel = credentials.get("rasa_addons.core.channels.webchat_plus.WebchatPlusInput")
                    if channel is None: channel = credentials.get("rasa_addons.core.channels.WebchatPlusInput")
                    if channel is None: channel = credentials.get("rasa_addons.core.channels.webchat.WebchatInput")
                    if channel is None: channel = credentials.get("rasa_addons.core.channels.WebchatInput", {})
                    props = channel.get("props", {})

            await sio.emit(
                "session_confirm",
                {"session_id": data["session_id"], "props": props},
                room=sid,
            )
            logger.debug(f"User {sid} connected to socketIO endpoint.")

        @sio.on(self.user_message_evt, namespace=self.namespace)
        async def handle_message(sid: Text, data: Dict) -> Any:
            output_channel = WebchatOutput(sio, self.bot_message_evt)

            if self.session_persistence:
                if not data.get("session_id"):
                    warnings.warn(
                        "A message without a valid sender_id "
                        "was received. This message will be "
                        "ignored. Make sure to set a proper "
                        "session id using the "
                        "`session_request` socketIO event."
                    )
                    return
                sender_id = data["session_id"]
            else:
                sender_id = sid
            

            if 'display' not in data['customData']:
                message = UserMessage(
                    data["message"],
                    output_channel,
                    sender_id,
                    input_channel=self.name(),
                    metadata=self.get_metadata(data),
                    )
                
                await on_new_message(message)
            
            elif data["customData"]["display"] != "clarity":
                
                message = UserMessage(
                    data["message"],
                    output_channel,
                    sender_id,
                    input_channel=self.name(),
                    metadata=self.get_metadata(data),
                    )
                
                await on_new_message(message)

            elif data["customData"]["display"] == "clarity":
                response = self.getUserContext(data)
                if response!="empty":
                    try:
                        if response.status_code == 200:
                            Results = json.loads(response.text)
                            logger.debug("Successfully authenticated")
                            url=data.get('customData').get('clarity').get('url')
                            a = url.split("/")
                            page=a[5]
                            metold=self.get_metadata(data)
                            logger.debug(metold)
                            
                            data.get('customData').get('clarity')['firstName']=Results.get("firstName")
                            data.get('customData').get('clarity')['userId']=Results.get("userId")
                            data.get('customData').get('clarity')['resourceId']=Results.get("resourceId")
                            data.get('customData').get('clarity')['lang']=Results.get("lang")
                            if 'version' in metold['clarity']:
                                data.get('customData').get('clarity')['version']=metold['clarity']['version'].replace(".","-")
                            else:
                                conv_version = Results.get("systemInfo").get("installations")[0].get("version").replace(".","-")
                                data.get('customData').get('clarity')['version']= re.search('^[0-9]{0,2}.[0-9]{0,2}.[0-9]{0,2}', conv_version).group()
                            data.get('customData').get('clarity')['page']=page
                            met=self.get_metadata(data)
                            logger.debug(met)
                            if data.get("message")!=None:
                                message = UserMessage(
                                    data["message"],
                                    output_channel,
                                    sender_id,
                                    input_channel=self.name(),
                                    metadata=self.get_metadata(data),
                                )
                        if data.get("message")!=None:
                            await on_new_message(message)
                    except:
                        try:
                            response.raise_for_status()
                        except requests.exceptions.HTTPError as error:
                            logger.debug(error)
                            await self.sio.disconnect(sid=sid,namespace=self.namespace)
                            logger.debug(f"User {sid} disconnected from socketIO endpoint,is not authorized")
                elif response=="empty":
                    pass
                else:
                    await self.sio.disconnect(sid=sid,namespace=self.namespace)
                    logger.debug(f"User {sid} disconnected from socketIO endpoint,is not authorized")


        return socketio_webhook
