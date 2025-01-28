```
sequenceDiagram
    participant c as Client
    participant tc as Client TEE
    participant t as TEE DB Proxy 
    participant v as Verifier


    c->>tc: Send query Q = {username, password, query[params]}
    tc->>v: Request nonce N1
    v->>tc: Send N1
    tc->>t: Request evidence E1, send N1 and Query name
    t->>t: Q requires attestation from TEE Client
    t->>v: Request nonce N2
    v->>t: Send N2
    t->>t: Compute E1
    t->>tc: Request evidence E2, send E1 and N2
    tc->>v: Send E1
    v->>v: Compute known E1 and compares to generated E1
    v->>v: Generate attestation A1 = S(E1, expiration)
    v->>tc: Send A1
    tc->>tc: Verify A1
    tc->>tc: Compute E2
    tc->>t: Send E2 and Q = {username, password, query[params]}
    t->>v: Send E2    
    v->>v: Compute known E2 and compares to generated E2
    v->>v: Generate attestation A2 = S(E2, expiration)
    v->>t: Send A2
    t->>t: Verify A2
    t->>t: Authenticates client
    t->>t: Verify client authorizations
    t->>t: Execute query
    t->>tc: Send response R = S(query result)
    tc->>tc: Verify R, process R
    tc->>c: Send S(R)
```