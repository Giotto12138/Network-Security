import playground
from .protocol import PassthroughClientFactory, PassthroughServerFactory

passthroughConnector = playground.Connector(protocolStack=(
    PassthroughClientFactory(),
    PassthroughServerFactory()))
playground.setConnector("poop", passthroughConnector)
playground.setConnector("poop", passthroughConnector)
