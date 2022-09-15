package de.adesso.softauthn;

import java.util.Optional;
import java.util.OptionalInt;

/**
 * Data class that contains information associated with a web <a href="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Origin">origin</a>.
 * <p>Users of this class should consider {@code null} values opaque origins.
 */
public class Origin {

    private final String scheme;
    private final String host;
    private final int port;
    private final String domain;

    /**
     * Create an origin with the given values.
     *
     * @param scheme The scheme
     * @param host The host.
     * @param port The port (or -1 if unspecified).
     * @param domain The domain (or {@code null} if unspecified).
     */
    public Origin(String scheme, String host, int port, String domain) {
        this.scheme = scheme;
        this.host = host;
        this.port = port;
        this.domain = domain;
    }

    /**
     * Get the scheme of this origin.
     *
     * @return the scheme.
     */
    public String getScheme() {
        return scheme;
    }

    /**
     * Get the host of this origin.
     *
     * @return The host.
     */
    public String getHost() {
        return host;
    }

    /**
     * Get the port of this origin.
     *
     * @return An optional containing the port if specified or the empty optional if this origin doesn't have a port.
     */
    public OptionalInt getPort() {
        return port == -1 ? OptionalInt.empty() : OptionalInt.of(port);
    }

    /**
     * Get the domain of this origin.
     *
     * @return An optional containing the domain if specified or the empty optional if this origin doesn't have a domain.
     */
    public Optional<String> getDomain() {
        return Optional.ofNullable(domain);
    }

    /**
     * Computes the <a href="https://html.spec.whatwg.org/multipage/origin.html#concept-origin-effective-domain">effective domain</a>
     * of this origin.
     *
     * @return The effective domain.
     */
    public String effectiveDomain() {
        return getDomain().orElse(getHost());
    }

    /**
     * Computes the <a href="https://html.spec.whatwg.org/multipage/origin.html#ascii-serialisation-of-an-origin">serialization</a>
     * of this origin.
     *
     * @return The serialization.
     */
    public String serialized() {
        return scheme + "://" + host + (port == -1 ? "" : ":" + port);
    }

    @Override
    public String toString() {
        return serialized();
    }
}
