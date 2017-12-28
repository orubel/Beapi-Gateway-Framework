

# BeApi(tm) Gateway Framework 
### Documentation not yet available
### Implementation not yet available


Fully reactive API Gateway providing automation and simplification of api's for scale. Some features include:

- **Request Data checking:** all request data for endpoints are checked early to see if proper data is being sent to throw errors EARLY and save on processing time.

- **Automated Batching:** all endpoints are batchable by default with AUTH ROLES assignable to restrict access. Batching can also be TOGGLED to turn this feature ON/OFF per endpoint.

- **Built-in CORS:** Cross Origin Request handling secures all endpoints from domains that you don't want.

- **JWT Tokens:** JWT Token handling for Javascript frontends to allow or better abstraction of the VIEW layer

- **Web Hooks:** Enables secured Web Hooks for any endpoint so your developers/users can get push notification on updates.

- **Throttling/Rate Limits:** Data Limits/Rate limits and Throttling for all API's through easy to configure options

- **Shared I/O state:** the data associated with functionality for REQUEST/RESPONSE (usually through annotations) has been removed and abstracted out to a single file per endpoint grouping. This allows for ON-THE-FLY reloading of the state and endpoint security. This also allows for easy update and synchronization will all services/processes that may share in the IO flow and need to synchronize this data (rather than duplicate).

- **Localized API Cache:** returned resources are cached,stored and updated with requesting ROLE/AUTH. Domains extend a base class that auto update this cache upon create/update/delete. This speeds up your api REQUEST/RESPONSE x10


**FAQ**

**Q: How hard is this to implement?**
**A:** BeApi is 'Plug-N-Play'. Merely install the plugin and it takes care of the 'REST'. The only thing you have to do is build an IO state file for each controller. This enables us to separate all IO data from functionality so it can be shared with other services in the architecture.

**Q: How do I implement the listener for IO state webhook on my proxy/Message queue?**
**A:** It merely requires an endpoint to send the data to. As a side project, I may actually supply a simple daemon in the future with ehCache to do this for people.
