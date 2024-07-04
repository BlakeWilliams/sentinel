# Sentinel APi Gateway

Sentinel is a basic proof-of-concept API gateway that attempts to:

- Centralize opaque authentication through a single point of entry using JWTs
- Route requests to the appropriate back-end service
- Handle rate limiting requests through middleware
- Be extensible to customize or extend the behavior of the gateway
