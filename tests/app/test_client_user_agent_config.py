from __future__ import annotations

import pytest

from pymax import Client, ExtraConfig, WebClient
from pymax.api.session.enums import DeviceType
from tests.conftest import mobile_user_agent


@pytest.mark.asyncio
async def test_client_config_restores_only_generated_user_agent_from_session() -> None:
    generated_client = Client(phone="+79990000000", app_version="26.14.1")
    explicit_user_agent = mobile_user_agent()
    explicit_client = Client(
        phone="+79990000000",
        app_version="26.14.1",
        extra_config=ExtraConfig(user_agent=explicit_user_agent),
    )

    generated_config = await generated_client._prepare_config()
    explicit_config = await explicit_client._prepare_config()

    assert generated_config.restore_user_agent_from_session is True
    assert explicit_config.restore_user_agent_from_session is False


@pytest.mark.asyncio
async def test_web_client_config_restores_only_generated_user_agent_from_session() -> None:
    generated_client = WebClient()
    explicit_user_agent = mobile_user_agent(DeviceType.WEB)
    explicit_client = WebClient(extra_config=ExtraConfig(user_agent=explicit_user_agent))

    generated_config = await generated_client._prepare_config()
    explicit_config = await explicit_client._prepare_config()

    assert generated_config.restore_user_agent_from_session is True
    assert explicit_config.restore_user_agent_from_session is False


@pytest.mark.asyncio
async def test_web_client_background_session_is_not_interactive() -> None:
    background = WebClient(extra_config=ExtraConfig(interactive=False))

    config = await background._prepare_config()

    assert config.interactive is False
    assert (await WebClient()._prepare_config()).interactive is True


@pytest.mark.asyncio
async def test_web_client_exposes_its_session_and_connection_loss() -> None:
    from types import SimpleNamespace

    from pymax.session.models import SessionInfo
    from pymax.types.domain.sync import SyncState

    client = WebClient()
    before_connect = client.session

    async def lost() -> None:
        raise ConnectionError("Connection lost")

    client._app = SimpleNamespace(
        session=SessionInfo(token="t", device_id="d", phone="", sync=SyncState(chats_sync=42))
    )
    client._connection = SimpleNamespace(wait_closed=lost)

    assert before_connect is None
    assert client.session.sync.chats_sync == 42
    with pytest.raises(ConnectionError):
        await client.wait_closed()
