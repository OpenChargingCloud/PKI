# Open Charging Cloud PKI

Public Key Infrastructures (PKIs) play a crucial role in ensuring the security and trustworthiness of digital communications.
This is especially important as whereever numerous competing companies, service providers, manufacturers, and other entities
have to coexist, distrust among each other can be a substantial barrier.

Unfortunately the traditional X.509 certificate standard is limited to a tree like structure having a single entity at its root
and a direct chain of trust from the root to each leaf entity. Nevertheless, the reality of relationships within e-mobility are
not simply one-to-one but involve multiple parties and are often many-to-many. This requires a more flexible and robust approach
to secure communication and trust. Therefore deviating from the traditional X.509 certificate standard will provide significant
benefits, given the inherent complexities of the sector and its daily politics.

Rather than modelling the e-mobility secotor as a linear hierarchy, it can better be represented as a graph of interconnected
enities, where multiple signatures per certificate are used to reflect and secure the complex, many-to-many relationships
inherent to the e-mobility ecosystem. Multi-signature certificates can capture the nuanced and multi-faceted relationships in
e-mobility. They allow for more than one party to sign and verify a certificate, which is particularly useful when multiple
entities need to agree on the authenticity of an entity or the validity of an operation. This multi-signature feature ensures
that a single compromised key does not lead to a system-wide security breach, enhancing the overall security posture of the
e-mobility ecosystem.

This new, graph-based PKI concept places an emphasis on collaborative security via a quorum of multiple private keys belonging
to various stakeholders at its center. In practice, it means that core certificates within the system will be signed by
multiple parties, reflecting their collective approval or agreement. This quorum-based validation principle not only boost
security but also introduces a unique sense of shared responsibility and trust among the diverse entities within the e-mobility
ecosystem. By requiring a majority of signatures, it ensures that no single entity can unilaterally validate a certificate,
preventing any potential misuse or compromise of a single private key from causing widespread damage.

In conclusion, this unique PKI with multi-signature quorum-based certificates represents a more accurate, secure, and flexible
approach to managing and securing the complex web of relationships in the e-mobility ecosystem. This approach moves away from the
limitations of the traditional X.509 model, embracing a graph-based representation of reality to ensure secure, trusted
digital communications in e-mobility.


## Fundamental Quorum

The following three [secp521r1](https://neuromancer.sk/std/nist/P-521) public keys define the fundamental 2/3 quorum.    
The encoding is base64.

```
Public Key A: BADD1aCeLgfcCUR8fUOhcz6KVJnhClIkEny1Sy4TTZvntLVInmVLezbX0c3606Y6ZZRqwuIBjAdJSwmEIqXlZZaSPQEKB2MBlGuHY/Zzhd13y+V/GZgv2WkzUlALd8hhAAMKCuNR15qSYeHuVrNPuht2/O3uRMlnj+Lla2TDYH6DP0ouDg==
Public Key B: BADk0FLDzC8745NqTw3A8jgSJJdRX9E7Cfj6vY4e8m1Sbc8qKoKfq5Jr4wjWfSIRAYD0dqp5mspRLyTWZu1CAKi7kAGFUADBZ024C38cpPMHrMgp6XVrpWoHnoH3uEKPNMa/u4oSBwM3pV7V1T3cuNybH0o1oxEUcG/WSqC51Td8LUOTqw==
Public Key C: BACXVG3Impsg27S+C/blhbaXUy6q73ff2YYSFxMWQv+aXunsZ4U2xF0dFBNBQt85knrZdfvFOauDfggsSX75NDg8vgFJCMRIvrCDG9uObRyVsdUgJSYxpOymYW2XtpW2xmrQadXbccjhRLPsQPzD7P9fSOnnby7Hb/z8gd2P7u7bdlyLYA==
```


## Core Certificates

```
Virtual PTB
BAFVws8yNnS4BA2U81zRftgoRwz6tCmkIXaPLApk5qMlNyK+ZA86ry81rviNUX9OqNsi/iIceT+t820x73kcFWPgewHSeqbkgatGSfUl8/80NailwIWqBqVRk2qrp+U3E4dHaU1vsINEQ+v5qrgbs3FZXCfHnJW6Mec2G04YuwFqo00TZg==

Charging Station Manufacturers 1
BAHQS8Nidech7dfV9kYnZU1e3oM59WYAwPBTLXvdeCuuVCswhKerv9v74alNtoEGHzFmirt8F4byPp9LC1PuuxvgOwDstWnIcEAop3l7BD/XnzcG6yHk2rdjeW1ppS0VdjAq1wnM6Rej5iKxq+b6hpFjIceodM4a/8v+QTCJEA+N6ZjYWQ==

Smart Energy Meter Manufacturers 1
BAFCVbvgh+ZcnMJr4e1XCN5WyO/jNINP0onuQk65pKvAvRm/3y2820kXkO7F2QzMDGD8nwPQkTuHZ5wiuoPnqf8NwwG10idlVZDEBjkuxLfBDe3FVQutP7u4FQtGhSbuA/HzZPCNSDdgtlQFGuMpI9FOdJ+2AqJr/b52lLVDzkkcAwBwfw==

Charging Station Operators 1
BAAbjGykjuGHF4pCAYlsCB8BnvEpGzR5k2Pmr7xdCylvasXnN3CpGlMRtgcmv1TG5f4O+XAeTqwcIT1lWxQwHYdvmgGtwgtDDcOgfMqFyazm6j2k6UkH3BbqpwqaThD5+Avbf0UMSs3GZgQVnwhxGr1Z37guNJqrWkY+ZiP60YvR0JdiTw==

E-Mobility Roaming Providers 1
BAF8hPattHqFZFk+oVtefcaJ5uF2G+DSVxB1a+f8sYSC87fLG439G4Q6Ku6jZc0rUaOTKiJkPkGJQZIZTpRYO0qqBgA6dXj15rCG+aLIhzkVKwmmu01ewUj/KIi4Mhvv98i6FriWfflqnJoxGFCFlZ0Ce4/eUHFbrK0oNuy8bvANupNIxQ==

E-Mobility Providers 1
BAFjgYZ8kz4PFXEg21Mg45b2f31dDpEE3Etr3K+mIvLgfk2UZhKzJK5LT7MUFo072L+E7Ryr2zMiCIo5ZXs/DlOrtQBM3cXz/hugoEnq1dfmmKhRX6xWH0vQFecGa/1p7qmJ3U0UohYEGlDmroPmhsT9/iGphjzZ/cjgXjznPROV/2b/lQ==

E-Vehicle Manufacturers 1
BAGs0xYywMkIetRSXL6Aoi19X7YeDAY2wTFxzNNflXfPib2V6IiqHGeXNdfAyiyuMwWsuFKu1PGSL1ln7KL0bvKcrwA9CA0zvnDZH17SFra9hbYgiuoaVcIvp1ZiILr20kDxOG4opnR4+Qi1xwbJeN6DKNdSq3P1N0KDB/Xx+LAro2HNpg==

Grid Operators 1
BAD1esW3tsFNQ84Tft1JUxGO4MSIdmayQWWXJq2yEeSscZWCM3a0jtC9KHiDjMJa7IUNmsokcVaUogEDzd9SJpTzSQEWihM6hZ2xwoykh6VLdXEW4792BEBydRhiUOEPGgMfoYSrN0q+kTcK5xMTRBIl55uYLXukM3PCTBkQTpYMz4IbBw==
```
