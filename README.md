# PKI

The public key infrastructure of the OpenChargingCloud: a
[WWCP_Node](https://github.com/OpenChargingCloud/WWCP_Node) that makes X.509
certificates - root CAs, sub-CAs, certificates for servers and clients, and
certificates for the key of a CSR - and keeps them, with a JSON API below
`/api/v1/pki` and a web interface at `/pki`.

It is not built alone: [PKICLI](https://github.com/OpenChargingCloud/PKICLI)
pins it beside the libraries it needs, builds it, and runs its tests.

| | |
|---|---|
| `PKI/PKI.cs` | the node: its names, its port (2360), its roles, its store |
| `PKI/PKIAccess.cs` | the resources `authorities` and `issuance`, and the roles `operator` and `registrar` |
| `PKI/Issuance/` | the store of certificates and what makes more of them: profiles, key algorithms, subjects and alternative names |
| `PKI/HTTPAPI/` | the routes below `v1/pki` |
| `PKI/Frontend/` | the web interface, bundled by webpack with what every node shares |
| `PKITests/` | the store, the API with its roles, and WWCP_Node's conformance suite asked of a PKI |


## Your participation

This software is Open Source under the **Affero GPL 3.0 license**.
We appreciate your participation in this ongoing project, and your help to
improve it and the e-mobility ICT in general. If you find bugs, want to
request a feature or send us a pull request, feel free to use the normal
GitHub features to do so. For this please read the Contributor License
Agreement carefully and send us a signed copy or use a similar free and
open license.
