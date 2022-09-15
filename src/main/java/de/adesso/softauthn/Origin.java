package de.adesso.softauthn;

import java.util.Optional;
import java.util.OptionalInt;

public class Origin {

    private final String scheme;
    private final String host;
    private final int port;
    private final String domain;

    public Origin(String scheme, String host, int port, String domain) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.domain = domain;
    }

    public String getScheme() {
        return scheme;
    }

    public String getHost() {
        return host;
    }

    public OptionalInt getPort() {
        return port == -1 ? OptionalInt.empty() : OptionalInt.of(port);
    }

    public Optional<String> getDomain() {
        return Optional.ofNullable(domain);
    }

    public String effectiveDomain() {
        return getDomain().orElse(getHost());
    }

    public String serialized() {
        return scheme + "://" + host + (port == -1 ? "" : ":" + port);
    }

    @Override
    public String toString() {
        return serialized();
    }
}
