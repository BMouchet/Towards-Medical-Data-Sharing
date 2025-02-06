```
sequenceDiagram
    participant c as Client
    participant t as TEE DB Proxy 
    participant v as Verifier


    c->>v: Request nonce N
    v->>c: Return N
    c->>t: Request evidence E, sends N
    t->>t: Compute E
    t->>c: Send E
    c->>v: Send E
    v->>v: Compute known E and compares to generated E
    v->>v: Generate attestation A = S(E, expiration)
    v->>c: Send A
    c->>c: Verify A
    c->>t: Send query Q = {username, password, query[params]} 
    t->>t: Authenticates client
    t->>t: Verify client authorizations
    t->>t: Execute query
    t->>c: Send response R = S(query result)
    c->>c: Verify R
```
