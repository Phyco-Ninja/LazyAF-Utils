#
# Copyright (C) 2020-2022 by Phyco-Ninja, < https://github.com/Phyco-Ninja >.
#
# This file is part of < https://github.com/Phyco-Ninja/LazyAF-Utils > project,
# and is released under the "GNU v3.0 License Agreement".
# Please see < https://github.com/Phyco-Ninja/LazyAF-Utils/blob/main/LICENSE >
#
# All rights reserved.
''' Motor MongoDB based storage engine for pyrogram '''

import base64
import asyncio
from time import time
from hashlib import blake2s, blake2b
from typing import List, Tuple, Any, Union

from motor.core import AgnosticDatabase, AgnosticCollection

from pyrogram.crypto import aes
from pyrogram.storage.storage import Storage
from pyrogram.storage.sqlite_storage import get_input_peer
from pyrogram.raw.types import InputPeerUser, InputPeerChat, InputPeerChannel

PeerLike = Union[InputPeerUser, InputPeerChat, InputPeerChannel]


class MongoStorage(Storage):
    """ Store Log in details & peers in MongoDB
        :parameters:
            > name: str = name of session [This will be used as aes key as well as session id]
            > database: AgnosticDatabase = Your MongoDB
        :usage:
            pass this instance as session_name while initializing pyrogram client
            >>> from pyrogram import Client
            >>> Client(MongoStorage("my_account", MongoDB))
    """
    MAX_UTTL = 12 * 60 * 60

    def __init__(self, name: str, database: AgnosticDatabase):
        super().__init__(name)
        self.key = blake2s(self.name.encode()).digest()
        self.i_v = blake2s("LazyAF_PyroThon_Client".encode()).digest()
        self.lock = asyncio.Lock()
        self.col: AgnosticCollection = database["SessionsAndPeers"]
        self.session_id: int = int(
            str(
                int.from_bytes(
                    blake2b(self.name.encode()).digest(), "big"
                )
            )[::16]
        )

    def _encode_auth_key(self, auth: bytes) -> str:
        """ encodes auth key with tgcrypto's aes & base64 """
        encrypted = aes.ige256_encrypt(
            key=self.key, iv=self.i_v, data=auth
        )
        return base64.urlsafe_b64encode(encrypted).decode()

    def _decode_auth_key(self, auth: str) -> bytes:
        """ decodes auth key """
        return aes.ige256_decrypt(
            key=self.key, iv=self.i_v,
            data=base64.urlsafe_b64decode(auth.encode())
        )

    async def _direct(self, key: str, option: Any) -> Union[bool, int, bytes, None]:
        """ Gets or save values depending on option """
        if option == object:
            return await self._get_value(key)
        return await self._save_value(key, option)

    async def _save_value(self, key: str, value: Any) -> None:
        """ save values to corresponding session fields """
        if key == "auth_key":
            value = self._encode_auth_key(value)
        async with self.lock:
            await self.col.update_one(
                {'sessionId': self.session_id},
                {"$set": {key: value, 'lastUpdated': time()}},
                upsert=True
            )

    async def _get_value(self, key: str):
        """ get values to corresponding session fields """
        data = await self.col.find_one({'sessionId': self.session_id})
        if not data:
            return None
        value = data.get(key)
        if key == "auth_key":
            value = self._decode_auth_key(value)
        return value

    async def dc_id(self, value: int = object):
        """ get or save dc id to mongo collection for log in """
        return await self._direct("dc_id", value)

    async def test_mode(self, value: bool = object):
        """ get or save test mode in db """
        return await self._direct("test_mode", value)

    async def auth_key(self, value: bytes = object):
        """ get or saves auth key to Mongo Collection """
        return await self._direct("auth_key", value)

    async def is_bot(self, value: bool = object):
        """ get or save is login as bot """
        return await self._direct("is_bot", value)

    async def user_id(self, value: int = object):
        """ get or save user id of login """
        return await self._direct("user_id", value)

    async def date(self, value: int = object):
        """ this is a mystery """
        return await self._direct("date", value)

    async def get_peer_by_id(self, peer_id: int) -> PeerLike:
        """ get peer from db via ids """
        try:
            data = await self.col.find_one(
                {'peerId': int(peer_id), 'fetchedBy': self.session_id}
            )
        except ValueError:
            data = None
        if not data:
            raise KeyError(f"ID not found: {peer_id}")
        return get_input_peer(
            data["peerId"], data["accessHash"], data["peerType"]
        )

    async def get_peer_by_phone_number(self, phone_number: str) -> PeerLike:
        """ get peer by phone number """
        data = await self.col.find_one(
            {'phoneNumber': phone_number, 'fetchedBy': self.session_id}
        )
        if not data:
            raise KeyError(f"Phone Number not found: {phone_number}")
        return get_input_peer(
            data["peerId"], data["accessHash"], data["peerType"]
        )

    async def get_peer_by_username(self, username: str) -> PeerLike:
        """ get peer by username """
        data = await self.col.find_one(
            {'peerUsername': username, 'fetchedBy': self.session_id}
        )
        if not data:
            raise KeyError(f"Username not found: {username}")
        if abs(time() - data["lastUpdated"]) > self.MAX_UTTL:
            raise KeyError(f"Username Expired: {username}")
        return get_input_peer(
            data["peerId"], data["accessHash"], data["peerType"]
        )

    async def update_peers(self, peers: List[Tuple[int, int, str, str, str]]):
        """ update peers """
        async with self.lock:
            for peer in peers:
                await self.col.update_one(
                    {"peerId": peer[0], "fetchedBy": self.session_id},
                    {"$set": {
                        'peerId': peer[0],
                        'accessHash': peer[1],
                        'peerType': peer[2],
                        'peerUsername': peer[3],
                        'phoneNumber': peer[4],
                        'lastUpdated': time()
                    }},
                    upsert=True
                )

    # :::::::::: [Deprecated Methods] ::::::::::
    @staticmethod
    async def export_session_string():
        """ packs and exports string session """
        raise DeprecationWarning("This method was removed in MongoStorage.")

    async def open(self):
        """ pass [Open session file] """

    async def save(self):
        """ pass [Execute session sql]"""

    async def close(self):
        """ pass [close sql connections] """

    async def delete(self):
        """ passing for now [Used to remove session files] """
