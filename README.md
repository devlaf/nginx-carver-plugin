# nginx-carver-plugin

### About
An nginx plugin that allows stripping token data from requests (e.g. incoming requests for a load balancing or proxying application or similar) and verifying them against a locally-running [carver](https://github.com/devlaf/carver) server.  Requests that contain an invalid token could then just be dropped.

I have not tested this thoroughly.
