import playground
from .protocol import SecureClientFactory, SecureServerFactory

secureConnector = playground.Connector(protocolStack=(
    SecureClientFactory(),
    SecureServerFactory()))
playground.setConnector("crap_shan_m2", secureConnector)
playground.setConnector("crap_shan_m2", secureConnector)
