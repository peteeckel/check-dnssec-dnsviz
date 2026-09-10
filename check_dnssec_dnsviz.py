#!/usr/bin/env python3

import argparse
import json
from pynag.Plugins import PluginHelper, ok, critical, warning, unknown

from datetime import datetime


DNSVIZ_RESULT_APPLE_COM = '''
{
    ".": {
        "status": "NOERROR",
        "queries": {
            "./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "./IN/DNSKEY",
                        "description": "RRset for ./DNSKEY",
                        "name": ".",
                        "ttl": 44138,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1 cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH /Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAW uEaEmYJ+GQPiwVVfstGwSA1McfFJUttT gq2Huu74KARhtA8wPo/N3XcyYQtNhz+q CM5NBb3ecx/naw6sYab9LxS6f2cU0q03 ++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV +tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI 34g1XVYrNlsCCTmNvFQIfzW5STFQFsQp izczyFn9r3LzSxxPCNwdlCG84bER0Bmd wqbF6Tanv+FxMOavrahkj4wIy5k=",
                            "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=",
                            "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hh OKkx3rLGXVaC6rXTsDc449/cidltpkyG wCJNnOAlFNKF2jBosZBU5eeHspaQWOmO ElZsjICMQMC3aeHbGiShvZsx4wMYSjH8 e7Vrhbu6irwCzVBApESjbUdpWWmEnhat hWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/ dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2 vaF18UYH9Z9GNUUeayffKC73PYc="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/20326",
                                "description": "RRSIG covering ./DNSKEY",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 20326,
                                "original_ttl": 172800,
                                "labels": 0,
                                "inception": "2026-08-30 00:00:00 UTC",
                                "expiration": "2026-09-20 00:00:00 UTC",
                                "signature": "PvfCYsLIvqwE52D32Fx+zL43nm8ojP/W3MbsbUu4IsBqewjFRvAv00Mp2ehX2IyjRUV2fhtHPFzL3G0PK9GucRv7Ab97RauaOiVJnAqqUjELQR4HedSNVnprjF8UUmRiXPOTXAD/WEWLAk9MOOcwF+xKeB4f8spcLMIVDA9r32afCpu2lhs/3rwDD687GCz2HN5y4/Ew5Wi8ZSD3TMtbaSoGOb73Zpzw0XqBk9PqBVEZPcR2bZkgPRQZRYz8Pwga658J1hhw6qn3eocf4WluAldJGd2wYvXLUrwdZESnYac0aq8OY2t3Z2MYoX1JnLQttItxyltVQIv8AoQnUMet/w==",
                                "ttl": 44138,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/38696",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 38696)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
                "ttl": 44138,
                "key_length": 2048,
                "key_tag": 38696,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/20326",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 20326)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
                "ttl": 44138,
                "key_length": 2048,
                "key_tag": 20326,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/57780",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 57780)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=",
                "ttl": 44138,
                "key_length": 2048,
                "key_tag": 57780,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ]
    },
    "com.": {
        "status": "NOERROR",
        "queries": {
            "com./IN/DS": {
                "answer": [
                    {
                        "id": "com./IN/DS",
                        "description": "RRset for com/DS",
                        "name": "com.",
                        "ttl": 712,
                        "type": "DS",
                        "rdata": [
                            "19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/57780",
                                "description": "RRSIG covering com/DS",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 57780,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-08 13:00:00 UTC",
                                "expiration": "2026-09-21 14:00:00 UTC",
                                "signature": "m0QBKoTxg7oyfhLavbh8WOL8ZbMvWw0dYLmVDpoL0AutQmd4rBa/bLOzMY+xX/ygL9RTeRBJvIMMPtPeFFEtbbTSdqORTAKUeQBsybT/PJ7M+GYFT1AGjWWOuDE8G8pctAEEt+1rnJzk0aXWYnPxnK93qg/p1ECoaL734HK4JfGbuj9xeU949VaaHowri3BtiQz1L0nsMuz897xzhm1LWtECXEfBbGSRzrNJjMn+jES0JqULHGWvtJv4h5o/IIzRyEsBQ93X7D+QARFz8rJpK9AvJZDLNIHqjfyHPjfT8yiM/ozBlQ9k+KtTIhQ5gNVKnfYiShgb9zIHhq5SfLNPxw==",
                                "ttl": 712,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "com./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "com./IN/DNSKEY",
                        "description": "RRset for com/DNSKEY",
                        "name": "com.",
                        "ttl": 712,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 13 o6onp+t66olg3PFhuIXaaatogT3OrqHr qt48IkYGuxwW8tSnQVMGyO+TSmp8sTRt kD9km+N/VQvvtqVM8ra9/Q==",
                            "257 3 13 tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JV NBitHzqpsGlz8huE61Ms9ANe6NSDLKJt iTBqfTJWDAywEp1FCsEINQ=="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_512_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "com./13/19718",
                                "description": "RRSIG covering com/DNSKEY",
                                "signer": "com.",
                                "algorithm": 13,
                                "key_tag": 19718,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-04 13:57:35 UTC",
                                "expiration": "2026-09-19 14:02:35 UTC",
                                "signature": "/d2tr1wyyq4wDt0J1bAwSi8Q19cS3RHVeYBo+d3MfUMNdN+Tjdr1VUgfPTKNnCVKjFNyrn51WlcZlncmH0jRBQ==",
                                "ttl": 712,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_512_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "13/41446",
                "description": "DNSKEY for com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 41446)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 13,
                "key": "o6onp+t66olg3PFhuIXaaatogT3OrqHrqt48IkYGuxwW8tSnQVMGyO+TSmp8sTRtkD9km+N/VQvvtqVM8ra9/Q==",
                "ttl": 712,
                "key_length": 512,
                "key_tag": 41446,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK",
                    "UDP_+_EDNS0_512_D_NK"
                ]
            },
            {
                "id": "13/19718",
                "description": "DNSKEY for com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 19718)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 13,
                "key": "tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==",
                "ttl": 712,
                "key_length": 512,
                "key_tag": 19718,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK",
                    "UDP_+_EDNS0_512_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "13/19718/2",
                    "description": "DS record(s) corresponding to DNSKEY for com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 19718)",
                    "algorithm": 13,
                    "key_tag": 19718,
                    "digest_type": 2,
                    "digest": "isuwzSj0ElCoCkkTiUJNNBUi2Uaw2gwCkfLT13HXgFo=",
                    "ttl": 712,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "apple.com.": {
        "status": "NOERROR",
        "queries": {
            "apple.com./IN/A": {
                "answer": [
                    {
                        "id": "apple.com./IN/A",
                        "description": "RRset for apple.com/A",
                        "name": "apple.com.",
                        "ttl": 900,
                        "type": "A",
                        "rdata": [
                            "17.253.144.10"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/NS": {
                "answer": [
                    {
                        "id": "apple.com./IN/NS",
                        "description": "RRset for apple.com/NS",
                        "name": "apple.com.",
                        "ttl": 97428,
                        "type": "NS",
                        "rdata": [
                            "a.ns.apple.com.",
                            "b.ns.apple.com.",
                            "c.ns.apple.com.",
                            "d.ns.apple.com."
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/CNAME": {
                "nodata": [
                    {
                        "id": "apple.com./IN/CNAME",
                        "soa": [
                            {
                                "id": "apple.com./IN/SOA",
                                "description": "RRset for apple.com/SOA",
                                "name": "apple.com.",
                                "ttl": 300,
                                "type": "SOA",
                                "rdata": [
                                    "ns-ext-prod.jackfruit.apple.com. dnscontact.apple.com. 2026090800 300 300 3628800 300"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/SOA": {
                "answer": [
                    {
                        "id": "apple.com./IN/SOA",
                        "description": "RRset for apple.com/SOA",
                        "name": "apple.com.",
                        "ttl": 43200,
                        "type": "SOA",
                        "rdata": [
                            "ns-ext-prod.jackfruit.apple.com. dnscontact.apple.com. 2026090800 300 300 3628800 300"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_N",
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_4096_D_NK_0x20",
                            "UDP_+_EDNS0_512_128_NK",
                            "UDP_+_EDNS0_512__O(100)NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "NO_COOKIE",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/MX": {
                "answer": [
                    {
                        "id": "apple.com./IN/MX",
                        "description": "RRset for apple.com/MX",
                        "name": "apple.com.",
                        "ttl": 3600,
                        "type": "MX",
                        "rdata": [
                            "10 mx-in.g.apple.com.",
                            "20 mx-in-ma.apple.com.",
                            "20 mx-in-rn.apple.com.",
                            "20 mx-in-sg.apple.com.",
                            "20 mx-in-hfd.apple.com.",
                            "20 mx-in-vib.apple.com."
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_512_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/TXT": {
                "answer": [
                    {
                        "id": "apple.com./IN/TXT",
                        "description": "RRset for apple.com/TXT",
                        "name": "apple.com.",
                        "ttl": 3600,
                        "type": "TXT",
                        "rdata": [
                            "\\"_eht2v8yfz1agpq7o4zdkkz3k0k86fyr\\"",
                            "\\"_khcec23xgc5b2lb981hup1csjb4cdnz\\"",
                            "\\"77a4a6de-da14-449c-83c4-85366e0f55f9\\"",
                            "\\"apple-domain-verification=X5Jt76bn3Dnmgzjj\\"",
                            "\\"lucidlink-verification=SCDW9V44GJHAVXKFS6ZY6EZ2YR\\"",
                            "\\"cerner-client-id=22dd1d8a-5e8b-4e1e-80ef-39bcdfd42798\\"",
                            "\\"cerner-client-id=ce3abf18-ee87-43b9-9927-9eb24b4bac4a\\"",
                            "\\"ValidationTokenValue=77a4a6de-da14-449c-83c4-85366e0f55f9\\"",
                            "\\"miro-verification=2494d255c4c50b1e521650a0659cbf3fa08b0072\\"",
                            "\\"facebook-domain-verification=n6cqjfucq6plswmtfbwnbbeu1qiq3v\\"",
                            "\\"v=spf1 include:_spf.apple.com include:_spf-txn.apple.com ~all\\"",
                            "\\"adobe-idp-site-verification=6bd5e74c-a3a0-4781-b2e1-e95399b5e11c\\"",
                            "\\"webexdomainverification.8C462=b728ec3f-dfc9-42f9-92cb-9ba8853cbee8\\"",
                            "\\"yahoo-verification-key=Ay+djyw0qWQgXKWGA/jstjYryTMrKb+PBXI5l8u5/jw=\\"",
                            "\\"google-site-verification=8M6XjQCzydT62jk8HY3VXPAG-nKDllTRV-JpA3-Ktyw\\"",
                            "\\"google-site-verification=L5kkMdiFI8npvb6KlHui84fJaCw5G64DWhaDRIAT4_c\\"",
                            "\\"google-site-verification=zBSq1mG5ssu2If-C17UAz_MzSZDcx03MVxmeDwMNc5w\\"",
                            "\\"Dynatrace-site-verification=7d881a7c-c13f-4146-9d27-2731459e2509__iqls0105tagglcsaul0m16ibrf\\"",
                            "\\"cisco-ci-domain-verification=6f3bfb849796a518061f8e8c4356f687a138502d86db742791685059176547dd\\"",
                            "\\"atlassian-domain-verification=mLabq99iaT8kquJechF6l31FAYoNUe3WB7tLpLFUiUYVJCse9SKq83hOJzFkwqrh\\"",
                            "\\"atlassian-domain-verification=qZD4TfnCAoAjCFQgafhoKQpOs9tviekNK4wYE4a5eK3XoRP06hXAvEp8SLU0v7fI\\"",
                            "\\"json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJpZW4wYWVHaGF0aG9oNmhhaHZpZWphaTNlYXkwYWh2YWhjaGFocXVhZWxlZTBZdWw0cGhpZXRoMHNvNXZpZXllZWNvaDRpZThzaGVlcGllVDNwYWVjaGVpVjZqb2h3aWVwaG82In0K\\"",
                            "\\"json:eyJ3aHkiOiJUaGlzIGlzIHRvIHRydW5jYXRlIFVEUCByZXNwb25zZXMgZm9yIFRYVCBxdWVyaWVzIHRvIGFwcGxlLmNvbSIsInBhZGRpbmciOiJxdWFoMGVpamFhNGVlajh0aWVkYWlnaG9jZWljaGFlOGVUb3ppZTVmdTVhaFRoMldlaU00aWsyaHVxdThpZXBoaWVxdW9oc2hlaXBhZWdoOUthZWw3b2NoaWVuZ2llem9lc2g1In0K\\""
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/AAAA": {
                "answer": [
                    {
                        "id": "apple.com./IN/AAAA",
                        "description": "RRset for apple.com/AAAA",
                        "name": "apple.com.",
                        "ttl": 900,
                        "type": "AAAA",
                        "rdata": [
                            "2620:149:af0::10"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/DS": {
                "nodata": [
                    {
                        "id": "apple.com./IN/DS",
                        "proof": [
                            {
                                "id": "NSEC3",
                                "description": "NSEC3 record(s) proving non-existence (NODATA) of apple.com/DS",
                                "nsec3": [
                                    {
                                        "id": "S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com./IN/NSEC3",
                                        "description": "RRset for S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com/NSEC3",
                                        "name": "S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com.",
                                        "ttl": 269,
                                        "type": "NSEC3",
                                        "rdata": [
                                            "1 1 0 - S0NU90LGV459KLHVQS37TUGA7QJQ5LPL NS DS RRSIG"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "com./13/41446",
                                                "description": "RRSIG covering s0nu36qs7289sfvuojaikthpmsr5ncl4.com/NSEC3",
                                                "signer": "com.",
                                                "algorithm": 13,
                                                "key_tag": 41446,
                                                "original_ttl": 900,
                                                "labels": 2,
                                                "inception": "2026-09-05 23:28:27 UTC",
                                                "expiration": "2026-09-13 00:38:27 UTC",
                                                "signature": "SRU+PLyN1E6jKTYzuWCsuYwdkxIxEXPz7I6i3IhymGNPgrql3YC6V6qbuvsWlggLALJHcm8r/A048Y7sx788Fg==",
                                                "ttl": 269,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    },
                                    {
                                        "id": "CK0POJMG874LJREF7EFN8430QVIT8BSM.com./IN/NSEC3",
                                        "description": "RRset for CK0POJMG874LJREF7EFN8430QVIT8BSM.com/NSEC3",
                                        "name": "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.",
                                        "ttl": 269,
                                        "type": "NSEC3",
                                        "rdata": [
                                            "1 1 0 - CK0Q35HRS4H76G6CHNB9414CJN6S5UPL NS SOA RRSIG DNSKEY NSEC3PARAM"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "com./13/41446",
                                                "description": "RRSIG covering ck0pojmg874ljref7efn8430qvit8bsm.com/NSEC3",
                                                "signer": "com.",
                                                "algorithm": 13,
                                                "key_tag": 41446,
                                                "original_ttl": 900,
                                                "labels": 2,
                                                "inception": "2026-09-07 23:16:14 UTC",
                                                "expiration": "2026-09-15 00:26:14 UTC",
                                                "signature": "UFj3+89gOovYUhSy2FrnNYD4FVaSNTNAXXc+ZniyqU3L8EASe95v0WcMczbabWpzv2yn+5f+puwfiKtxbqvthA==",
                                                "ttl": 269,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "opt_out": true,
                                "closest_encloser": "com.",
                                "closest_encloser_digest": "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.",
                                "next_closest_encloser": "apple.com.",
                                "next_closest_encloser_hash": "S0NU66FPJNR91AIOA0A6649SII2JVQ1A.com.",
                                "next_closest_encloser_covering": {
                                    "covered_name": "S0NU66FPJNR91AIOA0A6649SII2JVQ1A.com.",
                                    "nsec3_owner": "S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com.",
                                    "nsec3_next": "S0NU90LGV459KLHVQS37TUGA7QJQ5LPL.com."
                                },
                                "wildcard": "*.com.",
                                "wildcard_hash": "3RL2R262EG0N1AP5OLHAE7MAH2AH09HJ.com.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "com./IN/SOA",
                                "description": "RRset for com/SOA",
                                "name": "com.",
                                "ttl": 269,
                                "type": "SOA",
                                "rdata": [
                                    "a.gtld-servers.net. nstld.verisign-grs.com. 1788966508 1800 900 604800 900"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "com./13/41446",
                                        "description": "RRSIG covering com/SOA",
                                        "signer": "com.",
                                        "algorithm": 13,
                                        "key_tag": 41446,
                                        "original_ttl": 900,
                                        "labels": 1,
                                        "inception": "2026-09-09 13:58:28 UTC",
                                        "expiration": "2026-09-16 15:08:28 UTC",
                                        "signature": "VuP/Znok05x3l/PzNPk8F5pQewZ2DVSaEXp1uXjoiI7hVe0Q4IDEcbbZ0WjG2nkOteOeqdr2K2LIo3mKV99hdA==",
                                        "ttl": 269,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "apple.com./IN/DNSKEY": {
                "nodata": [
                    {
                        "id": "apple.com./IN/DNSKEY",
                        "soa": [
                            {
                                "id": "apple.com./IN/SOA",
                                "description": "RRset for apple.com/SOA",
                                "name": "apple.com.",
                                "ttl": 300,
                                "type": "SOA",
                                "rdata": [
                                    "ns-ext-prod.jackfruit.apple.com. dnscontact.apple.com. 2026090800 300 300 3628800 300"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_512_D_NK"
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_512_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "63hcd.0s563.apple.com./IN/A": {
                "nodata": [
                    {
                        "id": "63hcd.0s563.apple.com./IN/A",
                        "soa": [
                            {
                                "id": "apple.com./IN/SOA",
                                "description": "RRset for apple.com/SOA",
                                "name": "apple.com.",
                                "ttl": 300,
                                "type": "SOA",
                                "rdata": [
                                    "ns-ext-prod.jackfruit.apple.com. dnscontact.apple.com. 2026090800 300 300 3628800 300"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "delegation": {
            "insecurity_proof": [
                {
                    "id": "NSEC3",
                    "description": "NSEC3 record(s) proving non-existence (NODATA) of apple.com/DS",
                    "nsec3": [
                        {
                            "id": "S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com./IN/NSEC3",
                            "description": "RRset for S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com/NSEC3",
                            "name": "S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com.",
                            "ttl": 269,
                            "type": "NSEC3",
                            "rdata": [
                                "1 1 0 - S0NU90LGV459KLHVQS37TUGA7QJQ5LPL NS DS RRSIG"
                            ],
                            "servers": [
                                "192.168.46.106"
                            ],
                            "ns_names": [
                                "ns0."
                            ],
                            "query_options": [
                                "UDP_+_EDNS0_4096_D_NK"
                            ],
                            "rrsig": [
                                {
                                    "id": "com./13/41446",
                                    "description": "RRSIG covering s0nu36qs7289sfvuojaikthpmsr5ncl4.com/NSEC3",
                                    "signer": "com.",
                                    "algorithm": 13,
                                    "key_tag": 41446,
                                    "original_ttl": 900,
                                    "labels": 2,
                                    "inception": "2026-09-05 23:28:27 UTC",
                                    "expiration": "2026-09-13 00:38:27 UTC",
                                    "signature": "SRU+PLyN1E6jKTYzuWCsuYwdkxIxEXPz7I6i3IhymGNPgrql3YC6V6qbuvsWlggLALJHcm8r/A048Y7sx788Fg==",
                                    "ttl": 269,
                                    "status": "VALID",
                                    "servers": [
                                        "192.168.46.106"
                                    ],
                                    "ns_names": [
                                        "ns0."
                                    ],
                                    "query_options": [
                                        "UDP_+_EDNS0_4096_D_NK"
                                    ]
                                }
                            ]
                        },
                        {
                            "id": "CK0POJMG874LJREF7EFN8430QVIT8BSM.com./IN/NSEC3",
                            "description": "RRset for CK0POJMG874LJREF7EFN8430QVIT8BSM.com/NSEC3",
                            "name": "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.",
                            "ttl": 269,
                            "type": "NSEC3",
                            "rdata": [
                                "1 1 0 - CK0Q35HRS4H76G6CHNB9414CJN6S5UPL NS SOA RRSIG DNSKEY NSEC3PARAM"
                            ],
                            "servers": [
                                "192.168.46.106"
                            ],
                            "ns_names": [
                                "ns0."
                            ],
                            "query_options": [
                                "UDP_+_EDNS0_4096_D_NK"
                            ],
                            "rrsig": [
                                {
                                    "id": "com./13/41446",
                                    "description": "RRSIG covering ck0pojmg874ljref7efn8430qvit8bsm.com/NSEC3",
                                    "signer": "com.",
                                    "algorithm": 13,
                                    "key_tag": 41446,
                                    "original_ttl": 900,
                                    "labels": 2,
                                    "inception": "2026-09-07 23:16:14 UTC",
                                    "expiration": "2026-09-15 00:26:14 UTC",
                                    "signature": "UFj3+89gOovYUhSy2FrnNYD4FVaSNTNAXXc+ZniyqU3L8EASe95v0WcMczbabWpzv2yn+5f+puwfiKtxbqvthA==",
                                    "ttl": 269,
                                    "status": "VALID",
                                    "servers": [
                                        "192.168.46.106"
                                    ],
                                    "ns_names": [
                                        "ns0."
                                    ],
                                    "query_options": [
                                        "UDP_+_EDNS0_4096_D_NK"
                                    ]
                                }
                            ]
                        }
                    ],
                    "opt_out": true,
                    "closest_encloser": "com.",
                    "closest_encloser_digest": "CK0POJMG874LJREF7EFN8430QVIT8BSM.com.",
                    "next_closest_encloser": "apple.com.",
                    "next_closest_encloser_hash": "S0NU66FPJNR91AIOA0A6649SII2JVQ1A.com.",
                    "next_closest_encloser_covering": {
                        "covered_name": "S0NU66FPJNR91AIOA0A6649SII2JVQ1A.com.",
                        "nsec3_owner": "S0NU36QS7289SFVUOJAIKTHPMSR5NCL4.com.",
                        "nsec3_next": "S0NU90LGV459KLHVQS37TUGA7QJQ5LPL.com."
                    },
                    "wildcard": "*.com.",
                    "wildcard_hash": "3RL2R262EG0N1AP5OLHAE7MAH2AH09HJ.com.",
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "INSECURE"
        }
    }
}
'''
DNSVIZ_RESULT_HINDENBURGRING_COM = '''
{
    ".": {
        "status": "NOERROR",
        "queries": {
            "./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "./IN/DNSKEY",
                        "description": "RRset for ./DNSKEY",
                        "name": ".",
                        "ttl": 4883,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1 cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH /Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAW uEaEmYJ+GQPiwVVfstGwSA1McfFJUttT gq2Huu74KARhtA8wPo/N3XcyYQtNhz+q CM5NBb3ecx/naw6sYab9LxS6f2cU0q03 ++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV +tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI 34g1XVYrNlsCCTmNvFQIfzW5STFQFsQp izczyFn9r3LzSxxPCNwdlCG84bER0Bmd wqbF6Tanv+FxMOavrahkj4wIy5k=",
                            "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=",
                            "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hh OKkx3rLGXVaC6rXTsDc449/cidltpkyG wCJNnOAlFNKF2jBosZBU5eeHspaQWOmO ElZsjICMQMC3aeHbGiShvZsx4wMYSjH8 e7Vrhbu6irwCzVBApESjbUdpWWmEnhat hWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/ dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2 vaF18UYH9Z9GNUUeayffKC73PYc="
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/20326",
                                "description": "RRSIG covering ./DNSKEY",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 20326,
                                "original_ttl": 172800,
                                "labels": 0,
                                "inception": "2026-08-30 00:00:00 UTC",
                                "expiration": "2026-09-20 00:00:00 UTC",
                                "signature": "PvfCYsLIvqwE52D32Fx+zL43nm8ojP/W3MbsbUu4IsBqewjFRvAv00Mp2ehX2IyjRUV2fhtHPFzL3G0PK9GucRv7Ab97RauaOiVJnAqqUjELQR4HedSNVnprjF8UUmRiXPOTXAD/WEWLAk9MOOcwF+xKeB4f8spcLMIVDA9r32afCpu2lhs/3rwDD687GCz2HN5y4/Ew5Wi8ZSD3TMtbaSoGOb73Zpzw0XqBk9PqBVEZPcR2bZkgPRQZRYz8Pwga658J1hhw6qn3eocf4WluAldJGd2wYvXLUrwdZESnYac0aq8OY2t3Z2MYoX1JnLQttItxyltVQIv8AoQnUMet/w==",
                                "ttl": 4883,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/38696",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 38696)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
                "ttl": 4883,
                "key_length": 2048,
                "key_tag": 38696,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res200.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/20326",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 20326)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
                "ttl": 4883,
                "key_length": 2048,
                "key_tag": 20326,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res200.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/57780",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 57780)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=",
                "ttl": 4883,
                "key_length": 2048,
                "key_tag": 57780,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res200.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ]
    },
    "com.": {
        "status": "NOERROR",
        "queries": {
            "com./IN/DS": {
                "answer": [
                    {
                        "id": "com./IN/DS",
                        "description": "RRset for com/DS",
                        "name": "com.",
                        "ttl": 37365,
                        "type": "DS",
                        "rdata": [
                            "19718 13 2 8acbb0cd28f41250a80a491389424d341522d946b0da0c0291f2d3d771d7805a"
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/57780",
                                "description": "RRSIG covering com/DS",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 57780,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-09 04:00:00 UTC",
                                "expiration": "2026-09-22 05:00:00 UTC",
                                "signature": "Cw128VEloRUc817CDDDKDW8IFbfuyPybDQ2q9JD7CGs80nnnErUNDhcydzpfa1kraBYQ+RdifCZMzr9tZqB9Fpp/4I1cpvr5wZ0mTWcRN8rq9tz3yRzrgDGMiGQdtDGahNJaTnj5G0BH6V2c5tpp15YuMoATmM3AABuWuOHel4+tVgPSZhuEUrAetn8OCXSv29bar4y/7WFj2KftrqLP6jTrPOVoux5HftnknOhO8wjV2MHrEMD6/qUk90YU8WEqDsY2PMPy+iZvZnmD7Ftlc7p710b2ZviOo4nBydFcC84y5vuv7rRVBojVgmqEqVOawp+MYyaV9XUcRTlv8fRrOw==",
                                "ttl": 37365,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "com./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "com./IN/DNSKEY",
                        "description": "RRset for com/DNSKEY",
                        "name": "com.",
                        "ttl": 30253,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 13 o6onp+t66olg3PFhuIXaaatogT3OrqHr qt48IkYGuxwW8tSnQVMGyO+TSmp8sTRt kD9km+N/VQvvtqVM8ra9/Q==",
                            "257 3 13 tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JV NBitHzqpsGlz8huE61Ms9ANe6NSDLKJt iTBqfTJWDAywEp1FCsEINQ=="
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3",
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_512_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "com./13/19718",
                                "description": "RRSIG covering com/DNSKEY",
                                "signer": "com.",
                                "algorithm": 13,
                                "key_tag": 19718,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-04 13:57:35 UTC",
                                "expiration": "2026-09-19 14:02:35 UTC",
                                "signature": "/d2tr1wyyq4wDt0J1bAwSi8Q19cS3RHVeYBo+d3MfUMNdN+Tjdr1VUgfPTKNnCVKjFNyrn51WlcZlncmH0jRBQ==",
                                "ttl": 30253,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3",
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_512_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "13/19718",
                "description": "DNSKEY for com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 19718)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 13,
                "key": "tx8EZRAd2+K/DJRV0S+hbBzaRPS/G6JVNBitHzqpsGlz8huE61Ms9ANe6NSDLKJtiTBqfTJWDAywEp1FCsEINQ==",
                "ttl": 30253,
                "key_length": 512,
                "key_tag": 19718,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res200.zrh3",
                    "res700.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK",
                    "UDP_+_EDNS0_512_D_NK"
                ]
            },
            {
                "id": "13/41446",
                "description": "DNSKEY for com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 41446)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 13,
                "key": "o6onp+t66olg3PFhuIXaaatogT3OrqHrqt48IkYGuxwW8tSnQVMGyO+TSmp8sTRtkD9km+N/VQvvtqVM8ra9/Q==",
                "ttl": 30253,
                "key_length": 512,
                "key_tag": 41446,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res200.zrh3",
                    "res700.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK",
                    "UDP_+_EDNS0_512_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "13/19718/2",
                    "description": "DS record(s) corresponding to DNSKEY for com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 19718)",
                    "algorithm": 13,
                    "key_tag": 19718,
                    "digest_type": 2,
                    "digest": "isuwzSj0ElCoCkkTiUJNNBUi2Uaw2gwCkfLT13HXgFo=",
                    "ttl": 37365,
                    "status": "VALID",
                    "servers": [
                        "9.9.9.9"
                    ],
                    "ns_names": [
                        "ns1._dnsviz.*."
                    ],
                    "nsid_values": [
                        "res700.zrh3"
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "hindenburgring.com.": {
        "status": "NOERROR",
        "queries": {
            "hindenburgring.com./IN/A": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/A",
                        "description": "RRset for hindenburgring.com/A",
                        "name": "hindenburgring.com.",
                        "ttl": 3495,
                        "type": "A",
                        "rdata": [
                            "152.53.180.199"
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/36559",
                                "description": "RRSIG covering hindenburgring.com/A",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 36559,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-05 12:14:03 UTC",
                                "expiration": "2026-09-19 12:54:17 UTC",
                                "signature": "tWkeMvSSGPcMonyjFCXQZh2uxfo3/UzdPEP7Ev71ThGPjPzvdRMfaNHMUdZ1MzBXH+E3i+jFkI/jfNdrbkkpcw==",
                                "ttl": 3495,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/NS": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/NS",
                        "description": "RRset for hindenburgring.com/NS",
                        "name": "hindenburgring.com.",
                        "ttl": 43096,
                        "type": "NS",
                        "rdata": [
                            "ns.portal-to-web.de.",
                            "ns2.portal-to-web.de.",
                            "ns3.portal-to-web.de.",
                            "ns7.hindenburgring.com.",
                            "ns8.hindenburgring.com."
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/36559",
                                "description": "RRSIG covering hindenburgring.com/NS",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 36559,
                                "original_ttl": 86400,
                                "labels": 2,
                                "inception": "2026-09-09 11:22:08 UTC",
                                "expiration": "2026-09-23 12:03:11 UTC",
                                "signature": "F8rnvFgnKL+nS+eBEbD7crmSzoVP1dNT+XZDVQiird48Td1hcHGdrfFIj+nW/frk9jwSUO8VFWiyD2uBRI1MzA==",
                                "ttl": 43096,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/CNAME": {
                "nodata": [
                    {
                        "id": "hindenburgring.com./IN/CNAME",
                        "proof": [
                            {
                                "id": "NSEC3",
                                "description": "NSEC3 record(s) proving non-existence (NODATA) of hindenburgring.com/CNAME",
                                "nsec3": [
                                    {
                                        "id": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com./IN/NSEC3",
                                        "description": "RRset for 13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com/NSEC3",
                                        "name": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com.",
                                        "ttl": 3495,
                                        "type": "NSEC3",
                                        "rdata": [
                                            "1 0 0 - 1G938TRHSHNCKA05FI7BT5BLERLQJQ6C A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY CAA TYPE65534"
                                        ],
                                        "servers": [
                                            "9.9.9.9"
                                        ],
                                        "ns_names": [
                                            "ns1._dnsviz.*."
                                        ],
                                        "nsid_values": [
                                            "res200.zrh3"
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "hindenburgring.com./13/36559",
                                                "description": "RRSIG covering 13j7cfmgs24o5ibpa6jvsoboqjmiv2tb.hindenburgring.com/NSEC3",
                                                "signer": "hindenburgring.com.",
                                                "algorithm": 13,
                                                "key_tag": 36559,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2026-09-03 00:57:04 UTC",
                                                "expiration": "2026-09-17 01:19:09 UTC",
                                                "signature": "wksvadaT1fOfFPl+6nB75OEyqLbbBd8PNb7IjJFzsxz6+5SPIFDAfZCC0Fzc0/83+tjZtNxuaD4Pvm+aDVF4hg==",
                                                "ttl": 3495,
                                                "status": "VALID",
                                                "servers": [
                                                    "9.9.9.9"
                                                ],
                                                "ns_names": [
                                                    "ns1._dnsviz.*."
                                                ],
                                                "nsid_values": [
                                                    "res200.zrh3"
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_hash": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com.",
                                "sname_nsec_match": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com.",
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "hindenburgring.com./IN/SOA",
                                "description": "RRset for hindenburgring.com/SOA",
                                "name": "hindenburgring.com.",
                                "ttl": 3495,
                                "type": "SOA",
                                "rdata": [
                                    "ns7.hindenburgring.com. postmaster.hindenburgring.com. 1784219808 43200 7200 2419200 3600"
                                ],
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "hindenburgring.com./13/36559",
                                        "description": "RRSIG covering hindenburgring.com/SOA",
                                        "signer": "hindenburgring.com.",
                                        "algorithm": 13,
                                        "key_tag": 36559,
                                        "original_ttl": 3600,
                                        "labels": 2,
                                        "inception": "2026-09-09 12:56:37 UTC",
                                        "expiration": "2026-09-23 13:56:37 UTC",
                                        "signature": "NmQo81WLQNymSP6fcu3KfUgrr8nRXtF/dADpllK7tRTYEWbSKHlosIgmtQ49/0bpYqYGRbS/3KZsVOn/86VCBg==",
                                        "ttl": 3495,
                                        "status": "VALID",
                                        "servers": [
                                            "9.9.9.9"
                                        ],
                                        "ns_names": [
                                            "ns1._dnsviz.*."
                                        ],
                                        "nsid_values": [
                                            "res200.zrh3"
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/SOA": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/SOA",
                        "description": "RRset for hindenburgring.com/SOA",
                        "name": "hindenburgring.com.",
                        "ttl": 3497,
                        "type": "SOA",
                        "rdata": [
                            "ns7.hindenburgring.com. postmaster.hindenburgring.com. 1784219808 43200 7200 2419200 3600"
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3",
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_N",
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_4096_D_NK_0x20",
                            "UDP_+_EDNS0_512_128_NK",
                            "UDP_+_EDNS0_512__O(100)NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/36559",
                                "description": "RRSIG covering hindenburgring.com/SOA",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 36559,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-09 12:56:37 UTC",
                                "expiration": "2026-09-23 13:56:37 UTC",
                                "signature": "NmQo81WLQNymSP6fcu3KfUgrr8nRXtF/dADpllK7tRTYEWbSKHlosIgmtQ49/0bpYqYGRbS/3KZsVOn/86VCBg==",
                                "ttl": 3498,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3",
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_N",
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_4096_D_NK_0x20"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "NO_COOKIE",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/MX": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/MX",
                        "description": "RRset for hindenburgring.com/MX",
                        "name": "hindenburgring.com.",
                        "ttl": 43095,
                        "type": "MX",
                        "rdata": [
                            "10 mx1.hindenburgring.com."
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_512_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/36559",
                                "description": "RRSIG covering hindenburgring.com/MX",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 36559,
                                "original_ttl": 86400,
                                "labels": 2,
                                "inception": "2026-09-09 11:22:08 UTC",
                                "expiration": "2026-09-23 12:03:11 UTC",
                                "signature": "dZ8ElnoegSqa5RlQ1f3+Br2N50E+2eE8vUzt2Xr7UTef+rAIL4KCSO0OGauF83f+6ndXBp4c/+NcjB+Pm2QX4A==",
                                "ttl": 43095,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_512_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/TXT": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/TXT",
                        "description": "RRset for hindenburgring.com/TXT",
                        "name": "hindenburgring.com.",
                        "ttl": 60,
                        "type": "TXT",
                        "rdata": [
                            "\\"v=spf1 +ip6:2001:678:10c4::/48 +ip4:193.37.151.0/24 +ip6:2a0a:4cc0:c0:e92d::1 +ip4:152.53.180.199 -all\\""
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/36559",
                                "description": "RRSIG covering hindenburgring.com/TXT",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 36559,
                                "original_ttl": 60,
                                "labels": 2,
                                "inception": "2026-09-08 00:56:33 UTC",
                                "expiration": "2026-09-22 01:33:47 UTC",
                                "signature": "PUGyCZA+btDmm1AeH1c6Ve1sDE/4xkY8L/wjL2q/wQuG1jIvRPPs57osZWchoYdmM/YjPsjOvoKZPok1AbKYNQ==",
                                "ttl": 60,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/AAAA": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/AAAA",
                        "description": "RRset for hindenburgring.com/AAAA",
                        "name": "hindenburgring.com.",
                        "ttl": 3497,
                        "type": "AAAA",
                        "rdata": [
                            "2a0a:4cc0:c0:e92d::1"
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/36559",
                                "description": "RRSIG covering hindenburgring.com/AAAA",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 36559,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-05 12:14:03 UTC",
                                "expiration": "2026-09-19 12:54:17 UTC",
                                "signature": "LSiRKc8RvK9wgYbJXD2cOb+Qx+1++Ak7oPlL9UyHOWLUA5JiWxqtBACMOy2g3Dx4PZcuxmvTIN5KWIWvU5sy/Q==",
                                "ttl": 3497,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/DS": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/DS",
                        "description": "RRset for hindenburgring.com/DS",
                        "name": "hindenburgring.com.",
                        "ttl": 43092,
                        "type": "DS",
                        "rdata": [
                            "17669 13 2 deccdf9a767a96c883da6c80753fbf73ecd3984c49fbdd772b2934fd5cbfbb4f"
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res200.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "com./13/41446",
                                "description": "RRSIG covering hindenburgring.com/DS",
                                "signer": "com.",
                                "algorithm": 13,
                                "key_tag": 41446,
                                "original_ttl": 86400,
                                "labels": 2,
                                "inception": "2026-09-08 23:26:37 UTC",
                                "expiration": "2026-09-16 00:36:37 UTC",
                                "signature": "mjcx325fcOBi55JpoMWQ0E7kZXRriBZ2PTu7tlTumhCr68j2Ui9t/w6IIvzbJ3Spd9G0ejgW75k0/Um5GSD9qw==",
                                "ttl": 43092,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res200.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "hindenburgring.com./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "hindenburgring.com./IN/DNSKEY",
                        "description": "RRset for hindenburgring.com/DNSKEY",
                        "name": "hindenburgring.com.",
                        "ttl": 3495,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 13 MO0QPX7fnbDKrErf3TBD3FD9yBkSPNRw RqbSmeRHraoRSXCVwzuSMqSqqF4vnFUi +6LYMVyNHTVw6iFgBAa+ew==",
                            "257 3 13 FVgU8r1OLHz5KpL2ZdwvMR+Rpe37q3k6 0rv4mq1PWf56U5sYdrzUOeub/AuP1agG jPY3XDcVqwJby/s+HRNkOg=="
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_512_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "hindenburgring.com./13/17669",
                                "description": "RRSIG covering hindenburgring.com/DNSKEY",
                                "signer": "hindenburgring.com.",
                                "algorithm": 13,
                                "key_tag": 17669,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-02 19:50:19 UTC",
                                "expiration": "2026-09-16 20:50:19 UTC",
                                "signature": "ABbwYkPRH2nlj1fGHY2qqgw8u86ABdzJfMLeaJIk38x6yf5xpFP+lAu6ckpSdzWLl29Vp6tpWZmsI0b91j08Sw==",
                                "ttl": 3495,
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_512_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "0msgd.eg6n8.hindenburgring.com./IN/A": {
                "nodata": [
                    {
                        "id": "0msgd.eg6n8.hindenburgring.com./IN/A",
                        "proof": [
                            {
                                "id": "NSEC3",
                                "description": "NSEC3 record(s) proving non-existence (NODATA) of 0msgd.eg6n8.hindenburgring.com/A",
                                "nsec3": [
                                    {
                                        "id": "O0RCLG6RJK7OAVCNJARVTAFFG4BRNLKI.hindenburgring.com./IN/NSEC3",
                                        "description": "RRset for O0RCLG6RJK7OAVCNJARVTAFFG4BRNLKI.hindenburgring.com/NSEC3",
                                        "name": "O0RCLG6RJK7OAVCNJARVTAFFG4BRNLKI.hindenburgring.com.",
                                        "ttl": 3600,
                                        "type": "NSEC3",
                                        "rdata": [
                                            "1 0 0 - OJH58HCG0LK5TMN9LIMCVTK5PH2BHF1L TXT RRSIG"
                                        ],
                                        "servers": [
                                            "9.9.9.9"
                                        ],
                                        "ns_names": [
                                            "ns1._dnsviz.*."
                                        ],
                                        "nsid_values": [
                                            "res700.zrh3"
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "hindenburgring.com./13/36559",
                                                "description": "RRSIG covering o0rclg6rjk7oavcnjarvtaffg4brnlki.hindenburgring.com/NSEC3",
                                                "signer": "hindenburgring.com.",
                                                "algorithm": 13,
                                                "key_tag": 36559,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2026-09-03 19:26:45 UTC",
                                                "expiration": "2026-09-17 20:08:15 UTC",
                                                "signature": "60OKA52HUNHFvoRZB3Slm72ZjYRhl9LFzK8uBA7E4S8uX5QPh0c5V6cXWIE0KANBD/cMK45K6Q4lhV7xLC1cvA==",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "9.9.9.9"
                                                ],
                                                "ns_names": [
                                                    "ns1._dnsviz.*."
                                                ],
                                                "nsid_values": [
                                                    "res700.zrh3"
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    },
                                    {
                                        "id": "8MAL45FNAG9PSGCANARHRUFPGHNPJT57.hindenburgring.com./IN/NSEC3",
                                        "description": "RRset for 8MAL45FNAG9PSGCANARHRUFPGHNPJT57.hindenburgring.com/NSEC3",
                                        "name": "8MAL45FNAG9PSGCANARHRUFPGHNPJT57.hindenburgring.com.",
                                        "ttl": 3600,
                                        "type": "NSEC3",
                                        "rdata": [
                                            "1 0 0 - AJH16E8N9H8MOU86NG4R48F4PK9UPFKQ A AAAA RRSIG"
                                        ],
                                        "servers": [
                                            "9.9.9.9"
                                        ],
                                        "ns_names": [
                                            "ns1._dnsviz.*."
                                        ],
                                        "nsid_values": [
                                            "res700.zrh3"
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "hindenburgring.com./13/36559",
                                                "description": "RRSIG covering 8mal45fnag9psgcanarhrufpghnpjt57.hindenburgring.com/NSEC3",
                                                "signer": "hindenburgring.com.",
                                                "algorithm": 13,
                                                "key_tag": 36559,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2026-09-08 04:54:14 UTC",
                                                "expiration": "2026-09-22 05:52:39 UTC",
                                                "signature": "ZE34FeE5zL2MZ9ER68AKvK5JzWkGD+jK5ZFa2rcGgn/dL73T2n8PFKVxoBrwt8/GIl/2igE9cTxViwK/tLS3eA==",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "9.9.9.9"
                                                ],
                                                "ns_names": [
                                                    "ns1._dnsviz.*."
                                                ],
                                                "nsid_values": [
                                                    "res700.zrh3"
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    },
                                    {
                                        "id": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com./IN/NSEC3",
                                        "description": "RRset for 13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com/NSEC3",
                                        "name": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com.",
                                        "ttl": 3600,
                                        "type": "NSEC3",
                                        "rdata": [
                                            "1 0 0 - 1G938TRHSHNCKA05FI7BT5BLERLQJQ6C A NS SOA MX TXT AAAA RRSIG DNSKEY NSEC3PARAM CDS CDNSKEY CAA TYPE65534"
                                        ],
                                        "servers": [
                                            "9.9.9.9"
                                        ],
                                        "ns_names": [
                                            "ns1._dnsviz.*."
                                        ],
                                        "nsid_values": [
                                            "res700.zrh3"
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "hindenburgring.com./13/36559",
                                                "description": "RRSIG covering 13j7cfmgs24o5ibpa6jvsoboqjmiv2tb.hindenburgring.com/NSEC3",
                                                "signer": "hindenburgring.com.",
                                                "algorithm": 13,
                                                "key_tag": 36559,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2026-09-03 00:57:04 UTC",
                                                "expiration": "2026-09-17 01:19:09 UTC",
                                                "signature": "wksvadaT1fOfFPl+6nB75OEyqLbbBd8PNb7IjJFzsxz6+5SPIFDAfZCC0Fzc0/83+tjZtNxuaD4Pvm+aDVF4hg==",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "9.9.9.9"
                                                ],
                                                "ns_names": [
                                                    "ns1._dnsviz.*."
                                                ],
                                                "nsid_values": [
                                                    "res700.zrh3"
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "opt_out": false,
                                "closest_encloser": "hindenburgring.com.",
                                "closest_encloser_digest": "13J7CFMGS24O5IBPA6JVSOBOQJMIV2TB.hindenburgring.com.",
                                "next_closest_encloser": "eg6n8.hindenburgring.com.",
                                "next_closest_encloser_hash": "AD1UBI07748HRH6GOFB1H7EVOM3ELFOV.hindenburgring.com.",
                                "next_closest_encloser_covering": {
                                    "covered_name": "AD1UBI07748HRH6GOFB1H7EVOM3ELFOV.hindenburgring.com.",
                                    "nsec3_owner": "8MAL45FNAG9PSGCANARHRUFPGHNPJT57.hindenburgring.com.",
                                    "nsec3_next": "AJH16E8N9H8MOU86NG4R48F4PK9UPFKQ.hindenburgring.com."
                                },
                                "wildcard": "*.hindenburgring.com.",
                                "wildcard_hash": "O0RCLG6RJK7OAVCNJARVTAFFG4BRNLKI.hindenburgring.com.",
                                "wildcard_nsec_match": "O0RCLG6RJK7OAVCNJARVTAFFG4BRNLKI.hindenburgring.com.",
                                "status": "VALID",
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "hindenburgring.com./IN/SOA",
                                "description": "RRset for hindenburgring.com/SOA",
                                "name": "hindenburgring.com.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns7.hindenburgring.com. postmaster.hindenburgring.com. 1784219808 43200 7200 2419200 3600"
                                ],
                                "servers": [
                                    "9.9.9.9"
                                ],
                                "ns_names": [
                                    "ns1._dnsviz.*."
                                ],
                                "nsid_values": [
                                    "res700.zrh3"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "hindenburgring.com./13/36559",
                                        "description": "RRSIG covering hindenburgring.com/SOA",
                                        "signer": "hindenburgring.com.",
                                        "algorithm": 13,
                                        "key_tag": 36559,
                                        "original_ttl": 3600,
                                        "labels": 2,
                                        "inception": "2026-09-09 12:56:37 UTC",
                                        "expiration": "2026-09-23 13:56:37 UTC",
                                        "signature": "NmQo81WLQNymSP6fcu3KfUgrr8nRXtF/dADpllK7tRTYEWbSKHlosIgmtQ49/0bpYqYGRbS/3KZsVOn/86VCBg==",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "9.9.9.9"
                                        ],
                                        "ns_names": [
                                            "ns1._dnsviz.*."
                                        ],
                                        "nsid_values": [
                                            "res700.zrh3"
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "9.9.9.9"
                        ],
                        "ns_names": [
                            "ns1._dnsviz.*."
                        ],
                        "nsid_values": [
                            "res700.zrh3"
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "9.9.9.9": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "13/36559",
                "description": "DNSKEY for hindenburgring.com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 36559)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 13,
                "key": "MO0QPX7fnbDKrErf3TBD3FD9yBkSPNRwRqbSmeRHraoRSXCVwzuSMqSqqF4vnFUi+6LYMVyNHTVw6iFgBAa+ew==",
                "ttl": 3495,
                "key_length": 512,
                "key_tag": 36559,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res700.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK",
                    "UDP_+_EDNS0_512_D_NK"
                ]
            },
            {
                "id": "13/17669",
                "description": "DNSKEY for hindenburgring.com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 17669)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 13,
                "key": "FVgU8r1OLHz5KpL2ZdwvMR+Rpe37q3k60rv4mq1PWf56U5sYdrzUOeub/AuP1agGjPY3XDcVqwJby/s+HRNkOg==",
                "ttl": 3495,
                "key_length": 512,
                "key_tag": 17669,
                "servers": [
                    "9.9.9.9"
                ],
                "ns_names": [
                    "ns1._dnsviz.*."
                ],
                "nsid_values": [
                    "res700.zrh3"
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK",
                    "UDP_+_EDNS0_512_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "13/17669/2",
                    "description": "DS record(s) corresponding to DNSKEY for hindenburgring.com (algorithm 13 (ECDSA Curve P-256 with SHA-256), key tag 17669)",
                    "algorithm": 13,
                    "key_tag": 17669,
                    "digest_type": 2,
                    "digest": "3szfmnZ6lsiD2myAdT+/c+zTmExJ+913Kyk0/Vy/u08=",
                    "ttl": 43092,
                    "status": "VALID",
                    "servers": [
                        "9.9.9.9"
                    ],
                    "ns_names": [
                        "ns1._dnsviz.*."
                    ],
                    "nsid_values": [
                        "res200.zrh3"
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    }
}
'''
DNSVIZ_RESULT_FAIL01_DNSSEC_WORKS = '''
{
    ".": {
        "status": "NOERROR",
        "queries": {
            "./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "./IN/DNSKEY",
                        "description": "RRset for ./DNSKEY",
                        "name": ".",
                        "ttl": 43351,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1 cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH /Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAW uEaEmYJ+GQPiwVVfstGwSA1McfFJUttT gq2Huu74KARhtA8wPo/N3XcyYQtNhz+q CM5NBb3ecx/naw6sYab9LxS6f2cU0q03 ++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV +tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI 34g1XVYrNlsCCTmNvFQIfzW5STFQFsQp izczyFn9r3LzSxxPCNwdlCG84bER0Bmd wqbF6Tanv+FxMOavrahkj4wIy5k=",
                            "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=",
                            "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hh OKkx3rLGXVaC6rXTsDc449/cidltpkyG wCJNnOAlFNKF2jBosZBU5eeHspaQWOmO ElZsjICMQMC3aeHbGiShvZsx4wMYSjH8 e7Vrhbu6irwCzVBApESjbUdpWWmEnhat hWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/ dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2 vaF18UYH9Z9GNUUeayffKC73PYc="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/20326",
                                "description": "RRSIG covering ./DNSKEY",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 20326,
                                "original_ttl": 172800,
                                "labels": 0,
                                "inception": "2026-08-30 00:00:00 UTC",
                                "expiration": "2026-09-20 00:00:00 UTC",
                                "signature": "PvfCYsLIvqwE52D32Fx+zL43nm8ojP/W3MbsbUu4IsBqewjFRvAv00Mp2ehX2IyjRUV2fhtHPFzL3G0PK9GucRv7Ab97RauaOiVJnAqqUjELQR4HedSNVnprjF8UUmRiXPOTXAD/WEWLAk9MOOcwF+xKeB4f8spcLMIVDA9r32afCpu2lhs/3rwDD687GCz2HN5y4/Ew5Wi8ZSD3TMtbaSoGOb73Zpzw0XqBk9PqBVEZPcR2bZkgPRQZRYz8Pwga658J1hhw6qn3eocf4WluAldJGd2wYvXLUrwdZESnYac0aq8OY2t3Z2MYoX1JnLQttItxyltVQIv8AoQnUMet/w==",
                                "ttl": 43351,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/20326",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 20326)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
                "ttl": 43351,
                "key_length": 2048,
                "key_tag": 20326,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/57780",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 57780)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=",
                "ttl": 43351,
                "key_length": 2048,
                "key_tag": 57780,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/38696",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 38696)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
                "ttl": 43351,
                "key_length": 2048,
                "key_tag": 38696,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ]
    },
    "works.": {
        "status": "NOERROR",
        "queries": {
            "works./IN/DS": {
                "answer": [
                    {
                        "id": "works./IN/DS",
                        "description": "RRset for works/DS",
                        "name": "works.",
                        "ttl": 32131,
                        "type": "DS",
                        "rdata": [
                            "46672 8 2 0339dd99b86b96b8e437908e9aea3eb578fad0de211bd8cf7a4fe6885e0acdd2"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/57780",
                                "description": "RRSIG covering works/DS",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 57780,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-08 19:00:00 UTC",
                                "expiration": "2026-09-21 20:00:00 UTC",
                                "signature": "HJ4xY2Dw8pR0s/RsS4X7DUdbQbI+YW+ZJOGN0Z8Pp2Ck6gx/dF1jGJh29J5f47+jH5+nV1Xxxm32ShwJxYJZkPUv4RZnLdkJ4zn3pE8KVwoD8lQSEp/KjK2Ep5OjXSA7nj9Zc13xoC39NaVvb+BWnKAAt++Ejy4iGiAGQI1czYNFvEmEz8gNphO3GJC/fioXvkDu+q7eueUW//VsJskGpZQtq14F02Zz7GirNggLgiWKzcuY/F7h1vmFfXmQmrljqD5h7gS2s2zVkjMGuTmfy66vIldeIOupODvatnrlswvkLYJZAVSLOjQ+3Mhn4hqZUssVGMlL9Wql4m1IF0LReA==",
                                "ttl": 32131,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "works./IN/DNSKEY",
                        "description": "RRset for works/DNSKEY",
                        "name": "works.",
                        "ttl": 3555,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAcFibspf7LbUHI2O77ApMKzyW4Uj mic2ncmFuAptCU5riLgHDtBKQgb/bVHI W0EtiLlJK7UMXTInkWKya8YpZliI4LpY zn2wEVHqR+p4XFPUsbTF5iShO9eHSGQe KxDdCE1uvm+KgowaTYZXer1CWkLU5dXg w5NJ8aJc+yH3d2SN",
                            "256 3 8 AwEAAcW2xlVorpxgdGPtoShZkmy+GZXl mz7VQqQIAbD7TvBAND+94nKd/LGB/wQd pqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvs SUpky4MFF45iFy/NiaZr6qWAXWoI6rlZ NYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTs vesKUQDPNTihi34J",
                            "257 3 8 AwEAAcUAm28CTpQ/EyWVjStctnLxuNhY XJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2 D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQ dPLreAY06nGHDob73q8M6G4FhBpu++om g7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQ tC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka 1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtN BFlMRhFEeXivMga65EVt7Rti8Dq0ehP9 UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46K RG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRy C44xO4pIS1wunOlm8LO0D9W4dTE="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/46672",
                                "description": "RRSIG covering works/DNSKEY",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 46672,
                                "original_ttl": 3600,
                                "labels": 1,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "CAblYJ3CQwNY9RPbH4qC2o5p1uT+6SmIEoN2g4VL4pljc4sqbiNiXujMQi02QFXopGySdUbcM8MvQLcRtKUu+PdR0eJ2UHtVzPqMEuCk6XKxke0aXejLvo6BGFNKWA80T2Ka6gE8tvsXCpKDiEuWJ+HryJroI3oay2/QVdMRL+Dj75cx5/bdnJGl7/KS9FLcaibRMwfNjvpHwhSz+ZLwWIyaiBvKTvC84lks/F0+P11UTnUcA9/mDwLij5a4S0q2vr8M5zftLAoa6C+15lgaQ+M4f1GM8Lvs/Yq6VEzh81RMZknQJtrmtwS9j+Me7xudNqyiUUVV5V0/8XFog7M7EA==",
                                "ttl": 3555,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/62385",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 62385)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcFibspf7LbUHI2O77ApMKzyW4Ujmic2ncmFuAptCU5riLgHDtBKQgb/bVHIW0EtiLlJK7UMXTInkWKya8YpZliI4LpYzn2wEVHqR+p4XFPUsbTF5iShO9eHSGQeKxDdCE1uvm+KgowaTYZXer1CWkLU5dXgw5NJ8aJc+yH3d2SN",
                "ttl": 3555,
                "key_length": 1024,
                "key_tag": 62385,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/46672",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcUAm28CTpQ/EyWVjStctnLxuNhYXJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQdPLreAY06nGHDob73q8M6G4FhBpu++omg7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQtC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtNBFlMRhFEeXivMga65EVt7Rti8Dq0ehP9UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46KRG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRyC44xO4pIS1wunOlm8LO0D9W4dTE=",
                "ttl": 3555,
                "key_length": 2048,
                "key_tag": 46672,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/6363",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 6363)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcW2xlVorpxgdGPtoShZkmy+GZXlmz7VQqQIAbD7TvBAND+94nKd/LGB/wQdpqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvsSUpky4MFF45iFy/NiaZr6qWAXWoI6rlZNYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTsvesKUQDPNTihi34J",
                "ttl": 3555,
                "key_length": 1024,
                "key_tag": 6363,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/46672/2",
                    "description": "DS record(s) corresponding to DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                    "algorithm": 8,
                    "key_tag": 46672,
                    "digest_type": 2,
                    "digest": "AzndmbhrlrjkN5COmuo+tXj60N4hG9jPek/miF4KzdI=",
                    "ttl": 32131,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DS",
                        "description": "RRset for dnssec.works/DS",
                        "name": "dnssec.works.",
                        "ttl": 3332,
                        "type": "DS",
                        "rdata": [
                            "41779 8 2 a73a4215b94fd90c2e6b94bd0513c7a82c4a1e592fd686420573e611a1d29de1"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/6363",
                                "description": "RRSIG covering dnssec.works/DS",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 6363,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "OSMVJegb03XVAR3ljqkmFxYxPFAKsUVf4B+HvGV92HzgMLly25K5bhEYEDipP2jnEd1Dbct61DlVvZcH2fwRl6tPIF0+RyXeqYF/gY8kKs7DXPs5/bGxTgYd36mc6CtP71l4LCt4ZzqhmHeqj7e0acTChN70NaUWPOwg2gQdGv8=",
                                "ttl": 3332,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DNSKEY",
                        "description": "RRset for dnssec.works/DNSKEY",
                        "name": "dnssec.works.",
                        "ttl": 332,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n 39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqu cszYfwIpgGZb3b+6k1Xn8x6h5lHLipLA QVOJLq3/RZYB8VG2U6L6tu5tsTADPzT2 9boRAXnV3/yPk6sO9WqQcpQXIRkMOpTo u6EozHeBVgSphSWK4CEPWbR8BAmuswzu glqp05EWcRqJ++MG4ur4C4GXy3lSPiCw jAL1eJNqDBjSzqqptYdshtO0lqzFM0RC 36RoCQ==",
                            "257 3 8 AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz 03z5pZwZWpMRJu33+GQLswgZJJX/iOTc jwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7 DkvqQAJyDTfjVXEyX/745e/5CCPAkVGn aZihj9jqichokDfWkAOJvGxqg9HdqsLm XH3a2GrxFfvwsdSPuBwQmSVzURIyZMMx RC+GH2B+ADGWxJNvrspS0lf9svfkrdMv G4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS /6iB8FLBKnltYtsXuveovKp9Dwq+xllq vUQTkRK90aUQEQa8G8ukecJbIliCrPJH 7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7E VDcgwskGj/NdfEHUuBdw+Vr9eHu8x6ao U/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lq VP2Xw6cpROGviS6Z"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/41779",
                                "description": "RRSIG covering dnssec.works/DNSKEY",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 41779,
                                "original_ttl": 7200,
                                "labels": 2,
                                "inception": "2026-09-07 15:59:12 UTC",
                                "expiration": "2026-09-17 16:00:28 UTC",
                                "signature": "UiFr9a4PqfiuNTxqRF6LQz+12ymilKZ4r2mEVuPQYPm2zTSgk8baidhR2o+Us6YoblPW1PYbLjXSPxHoNFSAZMzLOKN9aqRhowKxoePn8EbnG9EiesNG4RJl0BcHItihzj6x+lUwKpVEDJn6CoO7/bGGd+aNlp7ixaEWXyO+DaW3qKDRRIFnnjihdxMrrY7QSg619F0AEbl8BgOF7reEIAnmRKsd5lGbQ9YAdLZYZAW9UlzJwSZEiHZdkjyAuh4qgZ+1Nazd41qTlzicuxr961EHB71oe7tpudCRCuhIs/pjBP12glcVQW0xBg0Kkbpb98oejJ3zrOeylO4N+YjezuPe1rwqYv2ksKMhL6Kc4h7Zde+DRSdFaVnLWktOS05oHXcTMW/Jcn34nyoV5kLyotStyIe5P2rt2c54zpeZ01s=",
                                "ttl": 332,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/63735",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 63735)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqucszYfwIpgGZb3b+6k1Xn8x6h5lHLipLAQVOJLq3/RZYB8VG2U6L6tu5tsTADPzT29boRAXnV3/yPk6sO9WqQcpQXIRkMOpTou6EozHeBVgSphSWK4CEPWbR8BAmuswzuglqp05EWcRqJ++MG4ur4C4GXy3lSPiCwjAL1eJNqDBjSzqqptYdshtO0lqzFM0RC36RoCQ==",
                "ttl": 332,
                "key_length": 1536,
                "key_tag": 63735,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/41779",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz03z5pZwZWpMRJu33+GQLswgZJJX/iOTcjwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7DkvqQAJyDTfjVXEyX/745e/5CCPAkVGnaZihj9jqichokDfWkAOJvGxqg9HdqsLmXH3a2GrxFfvwsdSPuBwQmSVzURIyZMMxRC+GH2B+ADGWxJNvrspS0lf9svfkrdMvG4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS/6iB8FLBKnltYtsXuveovKp9Dwq+xllqvUQTkRK90aUQEQa8G8ukecJbIliCrPJH7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7EVDcgwskGj/NdfEHUuBdw+Vr9eHu8x6aoU/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lqVP2Xw6cpROGviS6Z",
                "ttl": 332,
                "key_length": 2560,
                "key_tag": 41779,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/41779/2",
                    "description": "DS record(s) corresponding to DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                    "algorithm": 8,
                    "key_tag": 41779,
                    "digest_type": 2,
                    "digest": "pzpCFblP2Qwua5S9BRPHqCxKHlkv1oZCBXPmEaHSneE=",
                    "ttl": 3332,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "fail01.dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "fail01.dnssec.works./IN/A": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/A",
                        "description": "RRset for fail01.dnssec.works/A",
                        "name": "fail01.dnssec.works.",
                        "ttl": 3335,
                        "type": "A",
                        "rdata": [
                            "5.45.109.212"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "No RRSIG covering the RRset was returned in the response.  See RFC 4035, Sec. 3.1.1.",
                                "code": "MISSING_RRSIG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set (however, this server appeared to respond legitimately to other queries with the CD flag cleared).  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail01.dnssec.works./IN/NS": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/NS",
                        "description": "RRset for fail01.dnssec.works/NS",
                        "name": "fail01.dnssec.works.",
                        "ttl": 932,
                        "type": "NS",
                        "rdata": [
                            "ns2.myinfrastructure.org.",
                            "ns3.myinfrastructure.org."
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail01.dnssec.works./8/47688",
                                "description": "RRSIG covering fail01.dnssec.works/NS",
                                "signer": "fail01.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 47688,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "eBg3TUQi00F08NLY9dz1NWG0t7bJBpN4QQXsHO6FTXOqUjqRLwz4z1quiRUX4pguVtddQmuK+p6bX2KDMQXNCmA/6+g6VS/jD7ojk6/Bv2DEVtd7xiGB0CKEEDv8Aop8UbCUq6MCQiAHwWmiPFjCedsJWpSb0+ENrsFW9aM5cUN48K8EM09UzMxKyHOho3I6RavPT2F3yTVbc8m+oyeZ7kpoOYM4+x+tyf03fhIeAvf0WE7X3KGliagQpg1Irus1",
                                "ttl": 932,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail01.dnssec.works./IN/CNAME": {
                "nodata": [
                    {
                        "id": "fail01.dnssec.works./IN/CNAME",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail01.dnssec.works/CNAME",
                                "nsec": [
                                    {
                                        "id": "fail01.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail01.dnssec.works/NSEC",
                                        "name": "fail01.dnssec.works.",
                                        "ttl": 3600,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail01.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail01.dnssec.works./8/47688",
                                                "description": "RRSIG covering fail01.dnssec.works/NSEC",
                                                "signer": "fail01.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 47688,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "PZQUVMCYMJinvGmpKoB31JoY3KVVMiHAtEilde6VDpv3hc9tsCxmpPm3TUfIyjNuExHRAGHvgRQoAgFZZ2w79BscFxQmCzdMAouyGGwUPz/trl2TMVyK5X+sv4vhw8q2x2PBVA7aB6kkiFJm9/h6ROdkQIF39dXSyNOisISnopWBkJg4QkNVo9C2rPihOmmfWZeF01cqg2wAV2R8sPfDiL+5CQa9GrJri4WbBqOFovywXDdnAJjtaVrRuMraUEjm",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail01.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail01.dnssec.works./IN/SOA",
                                "description": "RRset for fail01.dnssec.works/SOA",
                                "name": "fail01.dnssec.works.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 7 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail01.dnssec.works./8/47688",
                                        "description": "RRSIG covering fail01.dnssec.works/SOA",
                                        "signer": "fail01.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 47688,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "jijUougeYZF6WrgKxZIa6JNHUHKBxrYTwsQn7d+juBYSJ8ZGH0v5otJqzu3Td7QF+PcbcMPzSXn78R4ynQfGCyPSVE85OIvxGqRBqK1mFAcp+s0IyBqX33Kd5QLGrD7VspN13zeUsYD6dAfBgNn/t9L43vc9ABQggAj8FIFYxFdbgPyLFbj/6109lyOuUc8CeUzBkNOqnbKEa8PBcnIjxftTobNlWJgeqz0IwT7ctDbVlHQw93D1v5+geZei3wNB",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail01.dnssec.works./IN/SOA": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/SOA",
                        "description": "RRset for fail01.dnssec.works/SOA",
                        "name": "fail01.dnssec.works.",
                        "ttl": 3600,
                        "type": "SOA",
                        "rdata": [
                            "ns2.myinfrastructure.org. hostmaster.strotmann.de. 7 86400 7200 3542400 3600"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_N",
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_4096_D_NK_0x20",
                            "UDP_+_EDNS0_512_128_NK",
                            "UDP_+_EDNS0_512__O(100)NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail01.dnssec.works./8/47688",
                                "description": "RRSIG covering fail01.dnssec.works/SOA",
                                "signer": "fail01.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 47688,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "jijUougeYZF6WrgKxZIa6JNHUHKBxrYTwsQn7d+juBYSJ8ZGH0v5otJqzu3Td7QF+PcbcMPzSXn78R4ynQfGCyPSVE85OIvxGqRBqK1mFAcp+s0IyBqX33Kd5QLGrD7VspN13zeUsYD6dAfBgNn/t9L43vc9ABQggAj8FIFYxFdbgPyLFbj/6109lyOuUc8CeUzBkNOqnbKEa8PBcnIjxftTobNlWJgeqz0IwT7ctDbVlHQw93D1v5+geZei3wNB",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_N",
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_4096_D_NK_0x20"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "NO_COOKIE",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "fail01.dnssec.works./IN/MX": {
                "nodata": [
                    {
                        "id": "fail01.dnssec.works./IN/MX",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail01.dnssec.works/MX",
                                "nsec": [
                                    {
                                        "id": "fail01.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail01.dnssec.works/NSEC",
                                        "name": "fail01.dnssec.works.",
                                        "ttl": 3600,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail01.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail01.dnssec.works./8/47688",
                                                "description": "RRSIG covering fail01.dnssec.works/NSEC",
                                                "signer": "fail01.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 47688,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "PZQUVMCYMJinvGmpKoB31JoY3KVVMiHAtEilde6VDpv3hc9tsCxmpPm3TUfIyjNuExHRAGHvgRQoAgFZZ2w79BscFxQmCzdMAouyGGwUPz/trl2TMVyK5X+sv4vhw8q2x2PBVA7aB6kkiFJm9/h6ROdkQIF39dXSyNOisISnopWBkJg4QkNVo9C2rPihOmmfWZeF01cqg2wAV2R8sPfDiL+5CQa9GrJri4WbBqOFovywXDdnAJjtaVrRuMraUEjm",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail01.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail01.dnssec.works./IN/SOA",
                                "description": "RRset for fail01.dnssec.works/SOA",
                                "name": "fail01.dnssec.works.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 7 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail01.dnssec.works./8/47688",
                                        "description": "RRSIG covering fail01.dnssec.works/SOA",
                                        "signer": "fail01.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 47688,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "jijUougeYZF6WrgKxZIa6JNHUHKBxrYTwsQn7d+juBYSJ8ZGH0v5otJqzu3Td7QF+PcbcMPzSXn78R4ynQfGCyPSVE85OIvxGqRBqK1mFAcp+s0IyBqX33Kd5QLGrD7VspN13zeUsYD6dAfBgNn/t9L43vc9ABQggAj8FIFYxFdbgPyLFbj/6109lyOuUc8CeUzBkNOqnbKEa8PBcnIjxftTobNlWJgeqz0IwT7ctDbVlHQw93D1v5+geZei3wNB",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail01.dnssec.works./IN/TXT": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/TXT",
                        "description": "RRset for fail01.dnssec.works/TXT",
                        "name": "fail01.dnssec.works.",
                        "ttl": 3600,
                        "type": "TXT",
                        "rdata": [
                            "\\"Yes, it's broken\\""
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "No RRSIG covering the RRset was returned in the response.  See RFC 4035, Sec. 3.1.1.",
                                "code": "MISSING_RRSIG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail01.dnssec.works./IN/AAAA": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/AAAA",
                        "description": "RRset for fail01.dnssec.works/AAAA",
                        "name": "fail01.dnssec.works.",
                        "ttl": 3599,
                        "type": "AAAA",
                        "rdata": [
                            "2a01:198:2b6:1000:203:2dff:fe29:8424"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "No RRSIG covering the RRset was returned in the response.  See RFC 4035, Sec. 3.1.1.",
                                "code": "MISSING_RRSIG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail01.dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/DS",
                        "description": "RRset for fail01.dnssec.works/DS",
                        "name": "fail01.dnssec.works.",
                        "ttl": 27,
                        "type": "DS",
                        "rdata": [
                            "52567 8 2 ccc39a9672fca2306fbfac175cf580f457a5abbdc4c28401e28355941c2aa16d"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/63735",
                                "description": "RRSIG covering fail01.dnssec.works/DS",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 63735,
                                "original_ttl": 30,
                                "labels": 3,
                                "inception": "2026-09-09 09:25:31 UTC",
                                "expiration": "2026-09-19 10:04:06 UTC",
                                "signature": "YAL2vblOtlF1di7CQp4K0/AS3AsBfh9kwZzFlCkxBtFpE/EHV/TAI00GY3SfauVyLqJwTk0c9r/a/W6r0G5fIoAUpNYZJNZDxZyervkdnjdvkuse5ke9Fypdr+DhIDX6nhQHSoUmrAlN80BXrGkMPtYalTVKEFR2LdBYS++XONL1LCV0jFovq9tPoX70pIzCdD3Ilwq6MLZnHGFvsetbqtTfwn0cYi4G46fEaU781ilZm2EmcZzLGrQIxJ3d+Z5N",
                                "ttl": 27,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail01.dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "fail01.dnssec.works./IN/DNSKEY",
                        "description": "RRset for fail01.dnssec.works/DNSKEY",
                        "name": "fail01.dnssec.works.",
                        "ttl": 3599,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAcSsTmBqIx56hVeog1INuGGdKpWk uYky7OZyHAt8uUXnuXFG31BFydZ74woO urKPucRNFZwUHiX66oSB5piryJxyE++a EIw+j4CMKcXNYBNmWXGno13HvK3xTP7J FHj/hWxehSLv9uVLuGRwKgjnfi9oGA45 e/iyNBcTKptSMkB3Kw4t/2CkrBapxmud fw7YC1NSrLNIuhxsd38c+F/QotycY8OU IKa1HhLeviTPIaZQRXwaj7cZt9ZMaGAG zlFPHQ==",
                            "257 3 8 AwEAAcWe/bliTxO4qRt1Frvy0BOiYD3o vvhxwju59BuCBD+lAQqLIvsvPD3v8K7O Kj7NCgY/pCUkbYbQN8f4FfTjwQjMdlHi JLoSrJymp0wuY26R89MlrmqekWgPOcR1 oT1N6/H8Suv9/bWOSy/W+RL1EZCQnGi3 RtA2KeKCJGUT0b7gppMBwSbrE6kYoFja 9CpG+0tnXCFJbsqZqpYPRJEzBcyTJYmx d4TyDmixtIjG3DnPLojxyjIWqS9KxJFA DeTk2A7Wh2ehimSMCXaRXrup9onV55Ga cmaHhWaXj0ZKpjdTsJRqTcyNvm+FcBdq 62f2qlrtoVDPGzj8i3eqWFbzZnp8IA2W mkaa0kFZlAxjZNKOPDgI+Ft1IujlEbJw R6jUb9xwqMFip6tSTEN5qYOGsouGUeNh DcEzFbu1RVjZd3Xf"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail01.dnssec.works./8/47688",
                                "description": "RRSIG covering fail01.dnssec.works/DNSKEY",
                                "signer": "fail01.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 47688,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "i8iDG2v5XlD6IRjKSN8W5Pv2mLscUuUr6E0k9tByIfFRpBaa24eRiJ4QJ0/GBYyinmFu6K+y19AUBWj56H9kx3I9Cgj6WBFSv86GdzeJoAPz5QfQgbgoDid1Vpyx+4stdqlrgP7+oBV3lFl+bGrgFnbamLEOZzolRSGrJhv9ICUzxd5j7uRcqGYfQgr1ykG2RXn7KWbCpVXXe1CdLZW3Ht+ybq5wwBKsWDlEumVNNiKRqQ/er1GBq3L9ygTn+gp0",
                                "ttl": 3599,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "id": "fail01.dnssec.works./8/52567",
                                "description": "RRSIG covering fail01.dnssec.works/DNSKEY",
                                "signer": "fail01.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 52567,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "OAFiVuTt0leen69Ivgpx30CAWi/tgO/pFgtvUDdpp9KlpRMHB6sct8R2co5hjZ5i9UlOTx+wScMeC0FimmUKQxLwgQ9mNGk+KgG3qKWrNUrfhit4WB1/WXI1zvTEtvtGjdejwF866ny5P3ZrJUmiRUmVlbZGNdzPiZps8q8ZTVc5u/s3vW0orcUEWBIgyAQGozwrERGFpbI3U74pF5MH6/ijyTJyxVeqzcT2w0TnBjLPDWFPOffzWOkeMQbWAQRDH2ZGDN7jy5ayo8QxxyEBWVE8HKjozJKTFhhHPivvJBK037ZVxAvzyWKqICRs7ief5ALe2LoAjjdYPk7w8T5NCb1IErpEXIDd1dK0epDS4cfKorMFfnsNGWalbf+Luwscf9o6/oZvUJms438+16TGDdkMoJJ8uALqtdd2QvE9Ewo=",
                                "ttl": 3599,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "mtqnw.k2oyt.fail01.dnssec.works./IN/A": {
                "nxdomain": [
                    {
                        "id": "mtqnw.k2oyt.fail01.dnssec.works./IN/A",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving the non-existence (NXDOMAIN) of mtqnw.k2oyt.fail01.dnssec.works",
                                "nsec": [
                                    {
                                        "id": "fail01.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail01.dnssec.works/NSEC",
                                        "name": "fail01.dnssec.works.",
                                        "ttl": 3600,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail01.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail01.dnssec.works./8/47688",
                                                "description": "RRSIG covering fail01.dnssec.works/NSEC",
                                                "signer": "fail01.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 47688,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "PZQUVMCYMJinvGmpKoB31JoY3KVVMiHAtEilde6VDpv3hc9tsCxmpPm3TUfIyjNuExHRAGHvgRQoAgFZZ2w79BscFxQmCzdMAouyGGwUPz/trl2TMVyK5X+sv4vhw8q2x2PBVA7aB6kkiFJm9/h6ROdkQIF39dXSyNOisISnopWBkJg4QkNVo9C2rPihOmmfWZeF01cqg2wAV2R8sPfDiL+5CQa9GrJri4WbBqOFovywXDdnAJjtaVrRuMraUEjm",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_covering": {
                                    "covered_name": "mtqnw.k2oyt.fail01.dnssec.works.",
                                    "nsec_owner": "fail01.dnssec.works.",
                                    "nsec_next": "why.fail01.dnssec.works."
                                },
                                "wildcard_covering": {
                                    "covered_name": "*.fail01.dnssec.works.",
                                    "nsec_owner": "fail01.dnssec.works.",
                                    "nsec_next": "why.fail01.dnssec.works."
                                },
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail01.dnssec.works./IN/SOA",
                                "description": "RRset for fail01.dnssec.works/SOA",
                                "name": "fail01.dnssec.works.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 7 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail01.dnssec.works./8/47688",
                                        "description": "RRSIG covering fail01.dnssec.works/SOA",
                                        "signer": "fail01.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 47688,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "jijUougeYZF6WrgKxZIa6JNHUHKBxrYTwsQn7d+juBYSJ8ZGH0v5otJqzu3Td7QF+PcbcMPzSXn78R4ynQfGCyPSVE85OIvxGqRBqK1mFAcp+s0IyBqX33Kd5QLGrD7VspN13zeUsYD6dAfBgNn/t9L43vc9ABQggAj8FIFYxFdbgPyLFbj/6109lyOuUc8CeUzBkNOqnbKEa8PBcnIjxftTobNlWJgeqz0IwT7ctDbVlHQw93D1v5+geZei3wNB",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/52567",
                "description": "DNSKEY for fail01.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 52567)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcWe/bliTxO4qRt1Frvy0BOiYD3ovvhxwju59BuCBD+lAQqLIvsvPD3v8K7OKj7NCgY/pCUkbYbQN8f4FfTjwQjMdlHiJLoSrJymp0wuY26R89MlrmqekWgPOcR1oT1N6/H8Suv9/bWOSy/W+RL1EZCQnGi3RtA2KeKCJGUT0b7gppMBwSbrE6kYoFja9CpG+0tnXCFJbsqZqpYPRJEzBcyTJYmxd4TyDmixtIjG3DnPLojxyjIWqS9KxJFADeTk2A7Wh2ehimSMCXaRXrup9onV55GacmaHhWaXj0ZKpjdTsJRqTcyNvm+FcBdq62f2qlrtoVDPGzj8i3eqWFbzZnp8IA2Wmkaa0kFZlAxjZNKOPDgI+Ft1IujlEbJwR6jUb9xwqMFip6tSTEN5qYOGsouGUeNhDcEzFbu1RVjZd3Xf",
                "ttl": 3599,
                "key_length": 2560,
                "key_tag": 52567,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/47688",
                "description": "DNSKEY for fail01.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 47688)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcSsTmBqIx56hVeog1INuGGdKpWkuYky7OZyHAt8uUXnuXFG31BFydZ74woOurKPucRNFZwUHiX66oSB5piryJxyE++aEIw+j4CMKcXNYBNmWXGno13HvK3xTP7JFHj/hWxehSLv9uVLuGRwKgjnfi9oGA45e/iyNBcTKptSMkB3Kw4t/2CkrBapxmudfw7YC1NSrLNIuhxsd38c+F/QotycY8OUIKa1HhLeviTPIaZQRXwaj7cZt9ZMaGAGzlFPHQ==",
                "ttl": 3599,
                "key_length": 1536,
                "key_tag": 47688,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/52567/2",
                    "description": "DS record(s) corresponding to DNSKEY for fail01.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 52567)",
                    "algorithm": 8,
                    "key_tag": 52567,
                    "digest_type": 2,
                    "digest": "zMOalnL8ojBvv6wXXPWA9Felq73EwoQB4oNVlBwqoW0=",
                    "ttl": 27,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    }
}
'''
DNSVIZ_RESULT_FAIL02_DNSSEC_WORKS = '''
{
    ".": {
        "status": "NOERROR",
        "queries": {
            "./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "./IN/DNSKEY",
                        "description": "RRset for ./DNSKEY",
                        "name": ".",
                        "ttl": 42152,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1 cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH /Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAW uEaEmYJ+GQPiwVVfstGwSA1McfFJUttT gq2Huu74KARhtA8wPo/N3XcyYQtNhz+q CM5NBb3ecx/naw6sYab9LxS6f2cU0q03 ++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV +tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI 34g1XVYrNlsCCTmNvFQIfzW5STFQFsQp izczyFn9r3LzSxxPCNwdlCG84bER0Bmd wqbF6Tanv+FxMOavrahkj4wIy5k=",
                            "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=",
                            "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hh OKkx3rLGXVaC6rXTsDc449/cidltpkyG wCJNnOAlFNKF2jBosZBU5eeHspaQWOmO ElZsjICMQMC3aeHbGiShvZsx4wMYSjH8 e7Vrhbu6irwCzVBApESjbUdpWWmEnhat hWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/ dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2 vaF18UYH9Z9GNUUeayffKC73PYc="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/20326",
                                "description": "RRSIG covering ./DNSKEY",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 20326,
                                "original_ttl": 172800,
                                "labels": 0,
                                "inception": "2026-08-30 00:00:00 UTC",
                                "expiration": "2026-09-20 00:00:00 UTC",
                                "signature": "PvfCYsLIvqwE52D32Fx+zL43nm8ojP/W3MbsbUu4IsBqewjFRvAv00Mp2ehX2IyjRUV2fhtHPFzL3G0PK9GucRv7Ab97RauaOiVJnAqqUjELQR4HedSNVnprjF8UUmRiXPOTXAD/WEWLAk9MOOcwF+xKeB4f8spcLMIVDA9r32afCpu2lhs/3rwDD687GCz2HN5y4/Ew5Wi8ZSD3TMtbaSoGOb73Zpzw0XqBk9PqBVEZPcR2bZkgPRQZRYz8Pwga658J1hhw6qn3eocf4WluAldJGd2wYvXLUrwdZESnYac0aq8OY2t3Z2MYoX1JnLQttItxyltVQIv8AoQnUMet/w==",
                                "ttl": 42152,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/20326",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 20326)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
                "ttl": 42152,
                "key_length": 2048,
                "key_tag": 20326,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/57780",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 57780)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=",
                "ttl": 42152,
                "key_length": 2048,
                "key_tag": 57780,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/38696",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 38696)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
                "ttl": 42152,
                "key_length": 2048,
                "key_tag": 38696,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ]
    },
    "works.": {
        "status": "NOERROR",
        "queries": {
            "works./IN/DS": {
                "answer": [
                    {
                        "id": "works./IN/DS",
                        "description": "RRset for works/DS",
                        "name": "works.",
                        "ttl": 30932,
                        "type": "DS",
                        "rdata": [
                            "46672 8 2 0339dd99b86b96b8e437908e9aea3eb578fad0de211bd8cf7a4fe6885e0acdd2"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/57780",
                                "description": "RRSIG covering works/DS",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 57780,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-08 19:00:00 UTC",
                                "expiration": "2026-09-21 20:00:00 UTC",
                                "signature": "HJ4xY2Dw8pR0s/RsS4X7DUdbQbI+YW+ZJOGN0Z8Pp2Ck6gx/dF1jGJh29J5f47+jH5+nV1Xxxm32ShwJxYJZkPUv4RZnLdkJ4zn3pE8KVwoD8lQSEp/KjK2Ep5OjXSA7nj9Zc13xoC39NaVvb+BWnKAAt++Ejy4iGiAGQI1czYNFvEmEz8gNphO3GJC/fioXvkDu+q7eueUW//VsJskGpZQtq14F02Zz7GirNggLgiWKzcuY/F7h1vmFfXmQmrljqD5h7gS2s2zVkjMGuTmfy66vIldeIOupODvatnrlswvkLYJZAVSLOjQ+3Mhn4hqZUssVGMlL9Wql4m1IF0LReA==",
                                "ttl": 30932,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "works./IN/DNSKEY",
                        "description": "RRset for works/DNSKEY",
                        "name": "works.",
                        "ttl": 2355,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAcFibspf7LbUHI2O77ApMKzyW4Uj mic2ncmFuAptCU5riLgHDtBKQgb/bVHI W0EtiLlJK7UMXTInkWKya8YpZliI4LpY zn2wEVHqR+p4XFPUsbTF5iShO9eHSGQe KxDdCE1uvm+KgowaTYZXer1CWkLU5dXg w5NJ8aJc+yH3d2SN",
                            "256 3 8 AwEAAcW2xlVorpxgdGPtoShZkmy+GZXl mz7VQqQIAbD7TvBAND+94nKd/LGB/wQd pqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvs SUpky4MFF45iFy/NiaZr6qWAXWoI6rlZ NYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTs vesKUQDPNTihi34J",
                            "257 3 8 AwEAAcUAm28CTpQ/EyWVjStctnLxuNhY XJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2 D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQ dPLreAY06nGHDob73q8M6G4FhBpu++om g7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQ tC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka 1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtN BFlMRhFEeXivMga65EVt7Rti8Dq0ehP9 UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46K RG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRy C44xO4pIS1wunOlm8LO0D9W4dTE="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/46672",
                                "description": "RRSIG covering works/DNSKEY",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 46672,
                                "original_ttl": 3600,
                                "labels": 1,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "CAblYJ3CQwNY9RPbH4qC2o5p1uT+6SmIEoN2g4VL4pljc4sqbiNiXujMQi02QFXopGySdUbcM8MvQLcRtKUu+PdR0eJ2UHtVzPqMEuCk6XKxke0aXejLvo6BGFNKWA80T2Ka6gE8tvsXCpKDiEuWJ+HryJroI3oay2/QVdMRL+Dj75cx5/bdnJGl7/KS9FLcaibRMwfNjvpHwhSz+ZLwWIyaiBvKTvC84lks/F0+P11UTnUcA9/mDwLij5a4S0q2vr8M5zftLAoa6C+15lgaQ+M4f1GM8Lvs/Yq6VEzh81RMZknQJtrmtwS9j+Me7xudNqyiUUVV5V0/8XFog7M7EA==",
                                "ttl": 2355,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/6363",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 6363)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcW2xlVorpxgdGPtoShZkmy+GZXlmz7VQqQIAbD7TvBAND+94nKd/LGB/wQdpqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvsSUpky4MFF45iFy/NiaZr6qWAXWoI6rlZNYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTsvesKUQDPNTihi34J",
                "ttl": 2355,
                "key_length": 1024,
                "key_tag": 6363,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/62385",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 62385)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcFibspf7LbUHI2O77ApMKzyW4Ujmic2ncmFuAptCU5riLgHDtBKQgb/bVHIW0EtiLlJK7UMXTInkWKya8YpZliI4LpYzn2wEVHqR+p4XFPUsbTF5iShO9eHSGQeKxDdCE1uvm+KgowaTYZXer1CWkLU5dXgw5NJ8aJc+yH3d2SN",
                "ttl": 2355,
                "key_length": 1024,
                "key_tag": 62385,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/46672",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcUAm28CTpQ/EyWVjStctnLxuNhYXJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQdPLreAY06nGHDob73q8M6G4FhBpu++omg7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQtC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtNBFlMRhFEeXivMga65EVt7Rti8Dq0ehP9UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46KRG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRyC44xO4pIS1wunOlm8LO0D9W4dTE=",
                "ttl": 2355,
                "key_length": 2048,
                "key_tag": 46672,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/46672/2",
                    "description": "DS record(s) corresponding to DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                    "algorithm": 8,
                    "key_tag": 46672,
                    "digest_type": 2,
                    "digest": "AzndmbhrlrjkN5COmuo+tXj60N4hG9jPek/miF4KzdI=",
                    "ttl": 30932,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DS",
                        "description": "RRset for dnssec.works/DS",
                        "name": "dnssec.works.",
                        "ttl": 2132,
                        "type": "DS",
                        "rdata": [
                            "41779 8 2 a73a4215b94fd90c2e6b94bd0513c7a82c4a1e592fd686420573e611a1d29de1"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/6363",
                                "description": "RRSIG covering dnssec.works/DS",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 6363,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "OSMVJegb03XVAR3ljqkmFxYxPFAKsUVf4B+HvGV92HzgMLly25K5bhEYEDipP2jnEd1Dbct61DlVvZcH2fwRl6tPIF0+RyXeqYF/gY8kKs7DXPs5/bGxTgYd36mc6CtP71l4LCt4ZzqhmHeqj7e0acTChN70NaUWPOwg2gQdGv8=",
                                "ttl": 2132,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DNSKEY",
                        "description": "RRset for dnssec.works/DNSKEY",
                        "name": "dnssec.works.",
                        "ttl": 6332,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n 39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqu cszYfwIpgGZb3b+6k1Xn8x6h5lHLipLA QVOJLq3/RZYB8VG2U6L6tu5tsTADPzT2 9boRAXnV3/yPk6sO9WqQcpQXIRkMOpTo u6EozHeBVgSphSWK4CEPWbR8BAmuswzu glqp05EWcRqJ++MG4ur4C4GXy3lSPiCw jAL1eJNqDBjSzqqptYdshtO0lqzFM0RC 36RoCQ==",
                            "257 3 8 AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz 03z5pZwZWpMRJu33+GQLswgZJJX/iOTc jwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7 DkvqQAJyDTfjVXEyX/745e/5CCPAkVGn aZihj9jqichokDfWkAOJvGxqg9HdqsLm XH3a2GrxFfvwsdSPuBwQmSVzURIyZMMx RC+GH2B+ADGWxJNvrspS0lf9svfkrdMv G4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS /6iB8FLBKnltYtsXuveovKp9Dwq+xllq vUQTkRK90aUQEQa8G8ukecJbIliCrPJH 7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7E VDcgwskGj/NdfEHUuBdw+Vr9eHu8x6ao U/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lq VP2Xw6cpROGviS6Z"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/41779",
                                "description": "RRSIG covering dnssec.works/DNSKEY",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 41779,
                                "original_ttl": 7200,
                                "labels": 2,
                                "inception": "2026-09-07 15:59:12 UTC",
                                "expiration": "2026-09-17 16:00:28 UTC",
                                "signature": "UiFr9a4PqfiuNTxqRF6LQz+12ymilKZ4r2mEVuPQYPm2zTSgk8baidhR2o+Us6YoblPW1PYbLjXSPxHoNFSAZMzLOKN9aqRhowKxoePn8EbnG9EiesNG4RJl0BcHItihzj6x+lUwKpVEDJn6CoO7/bGGd+aNlp7ixaEWXyO+DaW3qKDRRIFnnjihdxMrrY7QSg619F0AEbl8BgOF7reEIAnmRKsd5lGbQ9YAdLZYZAW9UlzJwSZEiHZdkjyAuh4qgZ+1Nazd41qTlzicuxr961EHB71oe7tpudCRCuhIs/pjBP12glcVQW0xBg0Kkbpb98oejJ3zrOeylO4N+YjezuPe1rwqYv2ksKMhL6Kc4h7Zde+DRSdFaVnLWktOS05oHXcTMW/Jcn34nyoV5kLyotStyIe5P2rt2c54zpeZ01s=",
                                "ttl": 6332,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/41779",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz03z5pZwZWpMRJu33+GQLswgZJJX/iOTcjwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7DkvqQAJyDTfjVXEyX/745e/5CCPAkVGnaZihj9jqichokDfWkAOJvGxqg9HdqsLmXH3a2GrxFfvwsdSPuBwQmSVzURIyZMMxRC+GH2B+ADGWxJNvrspS0lf9svfkrdMvG4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS/6iB8FLBKnltYtsXuveovKp9Dwq+xllqvUQTkRK90aUQEQa8G8ukecJbIliCrPJH7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7EVDcgwskGj/NdfEHUuBdw+Vr9eHu8x6aoU/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lqVP2Xw6cpROGviS6Z",
                "ttl": 6332,
                "key_length": 2560,
                "key_tag": 41779,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/63735",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 63735)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqucszYfwIpgGZb3b+6k1Xn8x6h5lHLipLAQVOJLq3/RZYB8VG2U6L6tu5tsTADPzT29boRAXnV3/yPk6sO9WqQcpQXIRkMOpTou6EozHeBVgSphSWK4CEPWbR8BAmuswzuglqp05EWcRqJ++MG4ur4C4GXy3lSPiCwjAL1eJNqDBjSzqqptYdshtO0lqzFM0RC36RoCQ==",
                "ttl": 6332,
                "key_length": 1536,
                "key_tag": 63735,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/41779/2",
                    "description": "DS record(s) corresponding to DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                    "algorithm": 8,
                    "key_tag": 41779,
                    "digest_type": 2,
                    "digest": "pzpCFblP2Qwua5S9BRPHqCxKHlkv1oZCBXPmEaHSneE=",
                    "ttl": 2132,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "fail02.dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "fail02.dnssec.works./IN/A": {
                "answer": [
                    {
                        "id": "fail02.dnssec.works./IN/A",
                        "description": "RRset for fail02.dnssec.works/A",
                        "name": "fail02.dnssec.works.",
                        "ttl": 3600,
                        "type": "A",
                        "rdata": [
                            "5.45.109.212"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail02.dnssec.works./8/31251",
                                "description": "RRSIG covering fail02.dnssec.works/A",
                                "signer": "fail02.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 31251,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "1983-04-01 20:20:20 UTC",
                                "expiration": "1983-05-01 20:20:20 UTC",
                                "signature": "kGxRo7GllaodTrujNNBI8/HgF1AuF+lntaxTPmIG9jhrwOhkyRyJjcL2Yl/gK3bUXGIwsD2VaI1WMyuigYEayChZfgfPxKlBs77bzA/ENv3QDcx8DFe5/SRM8TlFNSyXrbSqZi4xggFcx0xlumdbrp3KD0T/KwUexcsgIY2zDFI87cs0elyPw0FIvU2/aBGQhABO0/UWVQH4sHEAFk7MO/8YUR8vzkzoJTf7gpJeBsj6zEQjWBtRA4PmMbTkZmPg",
                                "ttl": 3600,
                                "status": "EXPIRED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "errors": [
                                    {
                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                        "code": "EXPIRATION_IN_PAST"
                                    }
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set (however, this server appeared to respond legitimately to other queries with the CD flag cleared).  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail02.dnssec.works./IN/NS": {
                "answer": [
                    {
                        "id": "fail02.dnssec.works./IN/NS",
                        "description": "RRset for fail02.dnssec.works/NS",
                        "name": "fail02.dnssec.works.",
                        "ttl": 3600,
                        "type": "NS",
                        "rdata": [
                            "ns2.myinfrastructure.org.",
                            "ns3.myinfrastructure.org."
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail02.dnssec.works./8/31251",
                                "description": "RRSIG covering fail02.dnssec.works/NS",
                                "signer": "fail02.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 31251,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "1983-04-01 20:20:20 UTC",
                                "expiration": "1983-05-01 20:20:20 UTC",
                                "signature": "SD94VWMjTCeMV6WpnfFGSPs5v/kwtQH7PpfR3sVoKhvwIYYBUvPHRBf8Vs7Im6NyWcKYF/rbyjJoMhEFWBNOSRbqHdexCIMTp7d8vM24/9H/+4F/v9s832u8NYAf2MQKJMWGjXu2CiRjshGrENlx3cFcIr6EcfQ7CcxDMsmMJcL3b0ZUu3ejpAg199rmBAJcaHTlx1qXuYKtrjs0hv/2Hc3FwYW/uqvtG5XwCo4NT/Mg6ShbNjSmVrI7SkUpNFqg",
                                "ttl": 3600,
                                "status": "EXPIRED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "errors": [
                                    {
                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                        "code": "EXPIRATION_IN_PAST"
                                    }
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set (however, this server appeared to respond legitimately to other queries with the CD flag cleared).  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail02.dnssec.works./IN/CNAME": {
                "nodata": [
                    {
                        "id": "fail02.dnssec.works./IN/CNAME",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail02.dnssec.works/CNAME",
                                "nsec": [
                                    {
                                        "id": "fail02.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail02.dnssec.works/NSEC",
                                        "name": "fail02.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "www.fail02.dnssec.works. A NS SOA AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail02.dnssec.works./8/31251",
                                                "description": "RRSIG covering fail02.dnssec.works/NSEC",
                                                "signer": "fail02.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 31251,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "1983-04-01 20:20:20 UTC",
                                                "expiration": "1983-05-01 20:20:20 UTC",
                                                "signature": "UV+blORhnVAIevlZdbjwMpbj6zGbe1m4K4RPHHYCEU57y18R6XCJCZE/xgGzMRWXsbp/S7rv+0RUnrNQyEGMXsd9L9EUh/jm+YuA25D+Q1Ur5gfWI7rVyeS3bJDgTYaoJUOyb3FwCFnov3cD/aikl0KxhlsCQjlLDWMrk4EYVYK0zfdN4MaeNxXbJ2e89L1nLyzH0b4zBKKPWjJbAvUMBVXbT6TD0gcyMqkuUjQfsyBJezbaopda3kSoYdK3z9xj",
                                                "ttl": 3598,
                                                "status": "EXPIRED",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ],
                                                "errors": [
                                                    {
                                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                        "code": "EXPIRATION_IN_PAST"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail02.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail02.dnssec.works./IN/SOA",
                                "description": "RRset for fail02.dnssec.works/SOA",
                                "name": "fail02.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 2 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail02.dnssec.works./8/31251",
                                        "description": "RRSIG covering fail02.dnssec.works/SOA",
                                        "signer": "fail02.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 31251,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "1983-04-01 20:20:20 UTC",
                                        "expiration": "1983-05-01 20:20:20 UTC",
                                        "signature": "gAV32mgyukbooi3UwhskrbdwFFgyIYDiWFDuVP4Onz0G0GH3R0NM+E5aT5s6BlX2hnJTkyA/tUSuf6zRRAbGM6gmg94CA3hQNkuoXvXQUAft9vlCAS4tC+FtHgBvpeyUZREAqwpzCuPtxMkXEoTNIqCG/7xNbSukOytz+datVD5+JY34hLskMyCC2FGqLv7/jV0jdfi4bnLbVLkqq1zLkKCn3DCRaejihAvylrlXOF9RAOM+rbCGRF7efTOJ9hof",
                                        "ttl": 3598,
                                        "status": "EXPIRED",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "errors": [
                                            {
                                                "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                "code": "EXPIRATION_IN_PAST"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail02.dnssec.works./IN/SOA": {
                "answer": [
                    {
                        "id": "fail02.dnssec.works./IN/SOA",
                        "description": "RRset for fail02.dnssec.works/SOA",
                        "name": "fail02.dnssec.works.",
                        "ttl": 3598,
                        "type": "SOA",
                        "rdata": [
                            "ns2.myinfrastructure.org. hostmaster.strotmann.de. 2 86400 7200 3542400 3600"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+C_EDNS0_4096_D_N",
                            "UDP_+C_EDNS0_4096_D_NK",
                            "UDP_+C_EDNS0_4096_D_NK_0x20",
                            "UDP_+C_EDNS0_512_128_NK",
                            "UDP_+C_EDNS0_512__O(100)NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail02.dnssec.works./8/31251",
                                "description": "RRSIG covering fail02.dnssec.works/SOA",
                                "signer": "fail02.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 31251,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "1983-04-01 20:20:20 UTC",
                                "expiration": "1983-05-01 20:20:20 UTC",
                                "signature": "gAV32mgyukbooi3UwhskrbdwFFgyIYDiWFDuVP4Onz0G0GH3R0NM+E5aT5s6BlX2hnJTkyA/tUSuf6zRRAbGM6gmg94CA3hQNkuoXvXQUAft9vlCAS4tC+FtHgBvpeyUZREAqwpzCuPtxMkXEoTNIqCG/7xNbSukOytz+datVD5+JY34hLskMyCC2FGqLv7/jV0jdfi4bnLbVLkqq1zLkKCn3DCRaejihAvylrlXOF9RAOM+rbCGRF7efTOJ9hof",
                                "ttl": 3598,
                                "status": "EXPIRED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_N",
                                    "UDP_+C_EDNS0_4096_D_NK",
                                    "UDP_+C_EDNS0_4096_D_NK_0x20"
                                ],
                                "errors": [
                                    {
                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                        "code": "EXPIRATION_IN_PAST"
                                    }
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "NO_COOKIE",
                                "response": "NO_COOKIE_OPT"
                            }
                        },
                        "errors": [
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set.  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_N"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_N"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail02.dnssec.works./IN/MX": {
                "nodata": [
                    {
                        "id": "fail02.dnssec.works./IN/MX",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail02.dnssec.works/MX",
                                "nsec": [
                                    {
                                        "id": "fail02.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail02.dnssec.works/NSEC",
                                        "name": "fail02.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "www.fail02.dnssec.works. A NS SOA AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail02.dnssec.works./8/31251",
                                                "description": "RRSIG covering fail02.dnssec.works/NSEC",
                                                "signer": "fail02.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 31251,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "1983-04-01 20:20:20 UTC",
                                                "expiration": "1983-05-01 20:20:20 UTC",
                                                "signature": "UV+blORhnVAIevlZdbjwMpbj6zGbe1m4K4RPHHYCEU57y18R6XCJCZE/xgGzMRWXsbp/S7rv+0RUnrNQyEGMXsd9L9EUh/jm+YuA25D+Q1Ur5gfWI7rVyeS3bJDgTYaoJUOyb3FwCFnov3cD/aikl0KxhlsCQjlLDWMrk4EYVYK0zfdN4MaeNxXbJ2e89L1nLyzH0b4zBKKPWjJbAvUMBVXbT6TD0gcyMqkuUjQfsyBJezbaopda3kSoYdK3z9xj",
                                                "ttl": 3598,
                                                "status": "EXPIRED",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ],
                                                "errors": [
                                                    {
                                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                        "code": "EXPIRATION_IN_PAST"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail02.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail02.dnssec.works./IN/SOA",
                                "description": "RRset for fail02.dnssec.works/SOA",
                                "name": "fail02.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 2 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail02.dnssec.works./8/31251",
                                        "description": "RRSIG covering fail02.dnssec.works/SOA",
                                        "signer": "fail02.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 31251,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "1983-04-01 20:20:20 UTC",
                                        "expiration": "1983-05-01 20:20:20 UTC",
                                        "signature": "gAV32mgyukbooi3UwhskrbdwFFgyIYDiWFDuVP4Onz0G0GH3R0NM+E5aT5s6BlX2hnJTkyA/tUSuf6zRRAbGM6gmg94CA3hQNkuoXvXQUAft9vlCAS4tC+FtHgBvpeyUZREAqwpzCuPtxMkXEoTNIqCG/7xNbSukOytz+datVD5+JY34hLskMyCC2FGqLv7/jV0jdfi4bnLbVLkqq1zLkKCn3DCRaejihAvylrlXOF9RAOM+rbCGRF7efTOJ9hof",
                                        "ttl": 3598,
                                        "status": "EXPIRED",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "errors": [
                                            {
                                                "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                "code": "EXPIRATION_IN_PAST"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail02.dnssec.works./IN/TXT": {
                "nodata": [
                    {
                        "id": "fail02.dnssec.works./IN/TXT",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail02.dnssec.works/TXT",
                                "nsec": [
                                    {
                                        "id": "fail02.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail02.dnssec.works/NSEC",
                                        "name": "fail02.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "www.fail02.dnssec.works. A NS SOA AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail02.dnssec.works./8/31251",
                                                "description": "RRSIG covering fail02.dnssec.works/NSEC",
                                                "signer": "fail02.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 31251,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "1983-04-01 20:20:20 UTC",
                                                "expiration": "1983-05-01 20:20:20 UTC",
                                                "signature": "UV+blORhnVAIevlZdbjwMpbj6zGbe1m4K4RPHHYCEU57y18R6XCJCZE/xgGzMRWXsbp/S7rv+0RUnrNQyEGMXsd9L9EUh/jm+YuA25D+Q1Ur5gfWI7rVyeS3bJDgTYaoJUOyb3FwCFnov3cD/aikl0KxhlsCQjlLDWMrk4EYVYK0zfdN4MaeNxXbJ2e89L1nLyzH0b4zBKKPWjJbAvUMBVXbT6TD0gcyMqkuUjQfsyBJezbaopda3kSoYdK3z9xj",
                                                "ttl": 3598,
                                                "status": "EXPIRED",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ],
                                                "errors": [
                                                    {
                                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                        "code": "EXPIRATION_IN_PAST"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail02.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail02.dnssec.works./IN/SOA",
                                "description": "RRset for fail02.dnssec.works/SOA",
                                "name": "fail02.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 2 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail02.dnssec.works./8/31251",
                                        "description": "RRSIG covering fail02.dnssec.works/SOA",
                                        "signer": "fail02.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 31251,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "1983-04-01 20:20:20 UTC",
                                        "expiration": "1983-05-01 20:20:20 UTC",
                                        "signature": "gAV32mgyukbooi3UwhskrbdwFFgyIYDiWFDuVP4Onz0G0GH3R0NM+E5aT5s6BlX2hnJTkyA/tUSuf6zRRAbGM6gmg94CA3hQNkuoXvXQUAft9vlCAS4tC+FtHgBvpeyUZREAqwpzCuPtxMkXEoTNIqCG/7xNbSukOytz+datVD5+JY34hLskMyCC2FGqLv7/jV0jdfi4bnLbVLkqq1zLkKCn3DCRaejihAvylrlXOF9RAOM+rbCGRF7efTOJ9hof",
                                        "ttl": 3598,
                                        "status": "EXPIRED",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "errors": [
                                            {
                                                "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                "code": "EXPIRATION_IN_PAST"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail02.dnssec.works./IN/AAAA": {
                "answer": [
                    {
                        "id": "fail02.dnssec.works./IN/AAAA",
                        "description": "RRset for fail02.dnssec.works/AAAA",
                        "name": "fail02.dnssec.works.",
                        "ttl": 3598,
                        "type": "AAAA",
                        "rdata": [
                            "2a01:198:2b6:1000:203:2dff:fe29:8424"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail02.dnssec.works./8/31251",
                                "description": "RRSIG covering fail02.dnssec.works/AAAA",
                                "signer": "fail02.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 31251,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "1983-04-01 20:20:20 UTC",
                                "expiration": "1983-05-01 20:20:20 UTC",
                                "signature": "p0A/g0Ng6riamoc5BcvHwch2Lvb/vTkqDG48jU5WCgXNazeJQDa0rIHXDWkSqB5kY6YzjSKB6PItpYENNVEZqrImPcQTN+I6fVQDR5PbnZyLfckjsxEXGh27/KYcDqbr0h69Gdt7y6l7MHdrGQIhKs1A1mh2CG8/UgtCvkmOUV1XXASDjZk887agIGet0gT5qrGnm1mOYRrmm8qLr+LQ/s6zzrp1IrNEbhy/5jCKy63dPA7oQg+39p9RUA8hRM9Q",
                                "ttl": 3598,
                                "status": "EXPIRED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "errors": [
                                    {
                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                        "code": "EXPIRATION_IN_PAST"
                                    }
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail02.dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "fail02.dnssec.works./IN/DS",
                        "description": "RRset for fail02.dnssec.works/DS",
                        "name": "fail02.dnssec.works.",
                        "ttl": 26,
                        "type": "DS",
                        "rdata": [
                            "2536 8 2 0a0f84dcd189fdb214607f2916a6d44f39c44ae3162072dc09fa243ae445d549"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/63735",
                                "description": "RRSIG covering fail02.dnssec.works/DS",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 63735,
                                "original_ttl": 30,
                                "labels": 3,
                                "inception": "2026-09-09 09:25:31 UTC",
                                "expiration": "2026-09-19 10:04:06 UTC",
                                "signature": "fW92Zx8KeuehwrBhI7PZmIq693aT9SaAJehs9jwWkME4w+fM5hRk6tsxgkz27u2DC0h6wM13684xxY4Qs8iDmLFhDYcN2UrGimTvESGJh1uz+xAFrr/mvH88b/PQcnMPPHO8oMYBWkHa6KLw6FX09wWI2LpLqmNAdy5CBsaHURaW6Kn1W2HQIOfA862h/QOej/nxFA0KGtNftUIOdJrK8rYN8xrqmq6NFeiVIxL5AFUyQpCM9G1pJP6JkeggL3TJ",
                                "ttl": 26,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail02.dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "fail02.dnssec.works./IN/DNSKEY",
                        "description": "RRset for fail02.dnssec.works/DNSKEY",
                        "name": "fail02.dnssec.works.",
                        "ttl": 3597,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAbNNkTB4IdLrJGfxUOi7/RjqaPZY lTk8mMEMGbCeJE/k78irSfXQspGESP+B 5YRFDt7PDAavHOetDZiFc3zuf71QZUAo eswEHB/+uDF7f0+VvvOsWcr2oM4igfIO RfQjjN7Ro2VE41pF8clxu5JLikCRZaoC 6OHZ74k87I0UT2R6EuIKSVxpQg1W69le OxoRTYVDcpZjSs4k7GHI925DTl9E4T1r wDjx1mSw7FelfdVpT0sZwU2eYNOnTeeX 0Z6HZw==",
                            "257 3 8 AwEAActEkFF1u3/zHFVipPG4Ycn2iaLV 0tgzm/zQa8bGOLVNrLt1ilbgHSx1VJiV JrkLfXiV4ObRT7rDFesweYwl54PbQF0H afZSuy8jAL8adMtV/noFYdC/lfrDOhQK BCtD83fyuo0eGImveh+8n67g332ZsJ8n lQGIh+6KnCGM+R4ogIAdczyGLCPBbmnG qBdZn42vtvlNYInjwLDT+4LzI6IiuROc xngcTcI8j92fWktppuVZTGojQX5EiMFH YMcdvb+nllPsuYqm9RsFzT9/v4ccOfti NBHgF4HUbbZArpL0JgL3i4sIZ6YzQDam YJhpgGY2ErowrrbfBeCORxAcdxC5zLqR 7I0NXRKJ4lnG9arJkC/eyHTzrPwcp46o +h25gYIF///pl7yO3ll5/MqPJQ7fgtr2 9g1Ok3MLIBZTQ4NZ"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail02.dnssec.works./8/2536",
                                "description": "RRSIG covering fail02.dnssec.works/DNSKEY",
                                "signer": "fail02.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 2536,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "1983-04-01 20:20:20 UTC",
                                "expiration": "1983-05-01 20:20:20 UTC",
                                "signature": "jp7Ka2BCjQyVpuFded40WMntj94Mbflv2bsM2LZN8mLeGznA/GDiZYgvgEyl3p/q+A/wqC11M674FnvelyNDTdtKtKQW1Mqf2z2mnZTmFbX/lPdeBhzFr0UxThm5sBeu8QXOL4ZzYvLj2PisIutZUun+Ht6Vj3qw/Pqi8nZIfDq9U2a5Cz7l2WHdfPfvWi6fxijBQ5F4wSIWMY3aa6mVakBJpGblH5rsDjwh4S9ovCaUEkf8j5X2nfI6k87hb/AqzzhMS7CMO21g+F1VjNqafMRsSt/qxhdSijQm6b5LlvFVxs+JBlt2tt5iBe8hQU7CQfKu8qjpnHJxgbT5UL+l8+c4z1vMFXeUbbvl2h0CrIEGzyJu9Y5qMd5FGKsS0Xn319S5RGy/azZwY6+gJ25dJDLhn/nzRH93WOo+DTWVnl8=",
                                "ttl": 3597,
                                "status": "EXPIRED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_NK"
                                ],
                                "errors": [
                                    {
                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                        "code": "EXPIRATION_IN_PAST"
                                    }
                                ]
                            },
                            {
                                "id": "fail02.dnssec.works./8/31251",
                                "description": "RRSIG covering fail02.dnssec.works/DNSKEY",
                                "signer": "fail02.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 31251,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "1983-04-01 20:20:20 UTC",
                                "expiration": "1983-05-01 20:20:20 UTC",
                                "signature": "mAxGq9nmJfnuWOQZ5vp8Ooqx1+/5RYkIY+8qAXniBh/GZBS6FNfLKW5OFCcuZxiNEJ0TWnUH/m/LVm5LmpnUH7bA2XteG9I35WcdF8ZzVZ8uv9TGt2bnxTi94zSKiO6zveui+AtiB2RHM7mqUxsBZDoA1F7M3Dk+HI81y86sR613oBnJCcEI2Su2d/G3YeyIrQ3UNR747eUQCh1LttdjZeoISrkJrfm/zIYsyYWJqWISUF8gzsJQ5sTFWyFDNV3u",
                                "ttl": 3597,
                                "status": "EXPIRED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_NK"
                                ],
                                "errors": [
                                    {
                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                        "code": "EXPIRATION_IN_PAST"
                                    }
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "cvuei.ve6mk.fail02.dnssec.works./IN/A": {
                "nxdomain": [
                    {
                        "id": "cvuei.ve6mk.fail02.dnssec.works./IN/A",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving the non-existence (NXDOMAIN) of cvuei.ve6mk.fail02.dnssec.works",
                                "nsec": [
                                    {
                                        "id": "fail02.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail02.dnssec.works/NSEC",
                                        "name": "fail02.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "www.fail02.dnssec.works. A NS SOA AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail02.dnssec.works./8/31251",
                                                "description": "RRSIG covering fail02.dnssec.works/NSEC",
                                                "signer": "fail02.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 31251,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "1983-04-01 20:20:20 UTC",
                                                "expiration": "1983-05-01 20:20:20 UTC",
                                                "signature": "UV+blORhnVAIevlZdbjwMpbj6zGbe1m4K4RPHHYCEU57y18R6XCJCZE/xgGzMRWXsbp/S7rv+0RUnrNQyEGMXsd9L9EUh/jm+YuA25D+Q1Ur5gfWI7rVyeS3bJDgTYaoJUOyb3FwCFnov3cD/aikl0KxhlsCQjlLDWMrk4EYVYK0zfdN4MaeNxXbJ2e89L1nLyzH0b4zBKKPWjJbAvUMBVXbT6TD0gcyMqkuUjQfsyBJezbaopda3kSoYdK3z9xj",
                                                "ttl": 3598,
                                                "status": "EXPIRED",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ],
                                                "errors": [
                                                    {
                                                        "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                        "code": "EXPIRATION_IN_PAST"
                                                    }
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_covering": {
                                    "covered_name": "cvuei.ve6mk.fail02.dnssec.works.",
                                    "nsec_owner": "fail02.dnssec.works.",
                                    "nsec_next": "www.fail02.dnssec.works."
                                },
                                "wildcard_covering": {
                                    "covered_name": "*.fail02.dnssec.works.",
                                    "nsec_owner": "fail02.dnssec.works.",
                                    "nsec_next": "www.fail02.dnssec.works."
                                },
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail02.dnssec.works./IN/SOA",
                                "description": "RRset for fail02.dnssec.works/SOA",
                                "name": "fail02.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 2 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail02.dnssec.works./8/31251",
                                        "description": "RRSIG covering fail02.dnssec.works/SOA",
                                        "signer": "fail02.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 31251,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "1983-04-01 20:20:20 UTC",
                                        "expiration": "1983-05-01 20:20:20 UTC",
                                        "signature": "gAV32mgyukbooi3UwhskrbdwFFgyIYDiWFDuVP4Onz0G0GH3R0NM+E5aT5s6BlX2hnJTkyA/tUSuf6zRRAbGM6gmg94CA3hQNkuoXvXQUAft9vlCAS4tC+FtHgBvpeyUZREAqwpzCuPtxMkXEoTNIqCG/7xNbSukOytz+datVD5+JY34hLskMyCC2FGqLv7/jV0jdfi4bnLbVLkqq1zLkKCn3DCRaejihAvylrlXOF9RAOM+rbCGRF7efTOJ9hof",
                                        "ttl": 3598,
                                        "status": "EXPIRED",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "errors": [
                                            {
                                                "description": "The Signature Expiration field of the RRSIG RR (1983-05-01 20:20:20+00:00) is 15836 days in the past.  See RFC 4035, Sec. 5.3.1.",
                                                "code": "EXPIRATION_IN_PAST"
                                            }
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/31251",
                "description": "DNSKEY for fail02.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 31251)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAbNNkTB4IdLrJGfxUOi7/RjqaPZYlTk8mMEMGbCeJE/k78irSfXQspGESP+B5YRFDt7PDAavHOetDZiFc3zuf71QZUAoeswEHB/+uDF7f0+VvvOsWcr2oM4igfIORfQjjN7Ro2VE41pF8clxu5JLikCRZaoC6OHZ74k87I0UT2R6EuIKSVxpQg1W69leOxoRTYVDcpZjSs4k7GHI925DTl9E4T1rwDjx1mSw7FelfdVpT0sZwU2eYNOnTeeX0Z6HZw==",
                "ttl": 3597,
                "key_length": 1536,
                "key_tag": 31251,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+C_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/2536",
                "description": "DNSKEY for fail02.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 2536)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAActEkFF1u3/zHFVipPG4Ycn2iaLV0tgzm/zQa8bGOLVNrLt1ilbgHSx1VJiVJrkLfXiV4ObRT7rDFesweYwl54PbQF0HafZSuy8jAL8adMtV/noFYdC/lfrDOhQKBCtD83fyuo0eGImveh+8n67g332ZsJ8nlQGIh+6KnCGM+R4ogIAdczyGLCPBbmnGqBdZn42vtvlNYInjwLDT+4LzI6IiuROcxngcTcI8j92fWktppuVZTGojQX5EiMFHYMcdvb+nllPsuYqm9RsFzT9/v4ccOftiNBHgF4HUbbZArpL0JgL3i4sIZ6YzQDamYJhpgGY2ErowrrbfBeCORxAcdxC5zLqR7I0NXRKJ4lnG9arJkC/eyHTzrPwcp46o+h25gYIF///pl7yO3ll5/MqPJQ7fgtr29g1Ok3MLIBZTQ4NZ",
                "ttl": 3597,
                "key_length": 2560,
                "key_tag": 2536,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+C_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/2536/2",
                    "description": "DS record(s) corresponding to DNSKEY for fail02.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 2536)",
                    "algorithm": 8,
                    "key_tag": 2536,
                    "digest_type": 2,
                    "digest": "Cg+E3NGJ/bIUYH8pFqbUTznESuMWIHLcCfokOuRF1Uk=",
                    "ttl": 26,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "BOGUS",
            "errors": [
                {
                    "description": "No valid RRSIGs made by a key corresponding to a DS RR were found covering the DNSKEY RRset, resulting in no secure entry point (SEP) into the zone.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                    "code": "NO_SEP",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "query_options": [
                        "TCP_+C_EDNS0_4096_D_NK"
                    ]
                }
            ]
        }
    }
}
'''
DNSVIZ_RESULT_FAIL03_DNSSEC_WORKS = '''
{
    ".": {
        "status": "NOERROR",
        "queries": {
            "./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "./IN/DNSKEY",
                        "description": "RRset for ./DNSKEY",
                        "name": ".",
                        "ttl": 42144,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1 cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH /Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAW uEaEmYJ+GQPiwVVfstGwSA1McfFJUttT gq2Huu74KARhtA8wPo/N3XcyYQtNhz+q CM5NBb3ecx/naw6sYab9LxS6f2cU0q03 ++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV +tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI 34g1XVYrNlsCCTmNvFQIfzW5STFQFsQp izczyFn9r3LzSxxPCNwdlCG84bER0Bmd wqbF6Tanv+FxMOavrahkj4wIy5k=",
                            "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=",
                            "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hh OKkx3rLGXVaC6rXTsDc449/cidltpkyG wCJNnOAlFNKF2jBosZBU5eeHspaQWOmO ElZsjICMQMC3aeHbGiShvZsx4wMYSjH8 e7Vrhbu6irwCzVBApESjbUdpWWmEnhat hWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/ dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2 vaF18UYH9Z9GNUUeayffKC73PYc="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/20326",
                                "description": "RRSIG covering ./DNSKEY",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 20326,
                                "original_ttl": 172800,
                                "labels": 0,
                                "inception": "2026-08-30 00:00:00 UTC",
                                "expiration": "2026-09-20 00:00:00 UTC",
                                "signature": "PvfCYsLIvqwE52D32Fx+zL43nm8ojP/W3MbsbUu4IsBqewjFRvAv00Mp2ehX2IyjRUV2fhtHPFzL3G0PK9GucRv7Ab97RauaOiVJnAqqUjELQR4HedSNVnprjF8UUmRiXPOTXAD/WEWLAk9MOOcwF+xKeB4f8spcLMIVDA9r32afCpu2lhs/3rwDD687GCz2HN5y4/Ew5Wi8ZSD3TMtbaSoGOb73Zpzw0XqBk9PqBVEZPcR2bZkgPRQZRYz8Pwga658J1hhw6qn3eocf4WluAldJGd2wYvXLUrwdZESnYac0aq8OY2t3Z2MYoX1JnLQttItxyltVQIv8AoQnUMet/w==",
                                "ttl": 42144,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/38696",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 38696)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
                "ttl": 42144,
                "key_length": 2048,
                "key_tag": 38696,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/20326",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 20326)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
                "ttl": 42144,
                "key_length": 2048,
                "key_tag": 20326,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/57780",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 57780)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=",
                "ttl": 42144,
                "key_length": 2048,
                "key_tag": 57780,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ]
    },
    "works.": {
        "status": "NOERROR",
        "queries": {
            "works./IN/DS": {
                "answer": [
                    {
                        "id": "works./IN/DS",
                        "description": "RRset for works/DS",
                        "name": "works.",
                        "ttl": 30924,
                        "type": "DS",
                        "rdata": [
                            "46672 8 2 0339dd99b86b96b8e437908e9aea3eb578fad0de211bd8cf7a4fe6885e0acdd2"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/57780",
                                "description": "RRSIG covering works/DS",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 57780,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-08 19:00:00 UTC",
                                "expiration": "2026-09-21 20:00:00 UTC",
                                "signature": "HJ4xY2Dw8pR0s/RsS4X7DUdbQbI+YW+ZJOGN0Z8Pp2Ck6gx/dF1jGJh29J5f47+jH5+nV1Xxxm32ShwJxYJZkPUv4RZnLdkJ4zn3pE8KVwoD8lQSEp/KjK2Ep5OjXSA7nj9Zc13xoC39NaVvb+BWnKAAt++Ejy4iGiAGQI1czYNFvEmEz8gNphO3GJC/fioXvkDu+q7eueUW//VsJskGpZQtq14F02Zz7GirNggLgiWKzcuY/F7h1vmFfXmQmrljqD5h7gS2s2zVkjMGuTmfy66vIldeIOupODvatnrlswvkLYJZAVSLOjQ+3Mhn4hqZUssVGMlL9Wql4m1IF0LReA==",
                                "ttl": 30924,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "works./IN/DNSKEY",
                        "description": "RRset for works/DNSKEY",
                        "name": "works.",
                        "ttl": 2347,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAcFibspf7LbUHI2O77ApMKzyW4Uj mic2ncmFuAptCU5riLgHDtBKQgb/bVHI W0EtiLlJK7UMXTInkWKya8YpZliI4LpY zn2wEVHqR+p4XFPUsbTF5iShO9eHSGQe KxDdCE1uvm+KgowaTYZXer1CWkLU5dXg w5NJ8aJc+yH3d2SN",
                            "256 3 8 AwEAAcW2xlVorpxgdGPtoShZkmy+GZXl mz7VQqQIAbD7TvBAND+94nKd/LGB/wQd pqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvs SUpky4MFF45iFy/NiaZr6qWAXWoI6rlZ NYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTs vesKUQDPNTihi34J",
                            "257 3 8 AwEAAcUAm28CTpQ/EyWVjStctnLxuNhY XJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2 D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQ dPLreAY06nGHDob73q8M6G4FhBpu++om g7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQ tC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka 1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtN BFlMRhFEeXivMga65EVt7Rti8Dq0ehP9 UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46K RG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRy C44xO4pIS1wunOlm8LO0D9W4dTE="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/46672",
                                "description": "RRSIG covering works/DNSKEY",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 46672,
                                "original_ttl": 3600,
                                "labels": 1,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "CAblYJ3CQwNY9RPbH4qC2o5p1uT+6SmIEoN2g4VL4pljc4sqbiNiXujMQi02QFXopGySdUbcM8MvQLcRtKUu+PdR0eJ2UHtVzPqMEuCk6XKxke0aXejLvo6BGFNKWA80T2Ka6gE8tvsXCpKDiEuWJ+HryJroI3oay2/QVdMRL+Dj75cx5/bdnJGl7/KS9FLcaibRMwfNjvpHwhSz+ZLwWIyaiBvKTvC84lks/F0+P11UTnUcA9/mDwLij5a4S0q2vr8M5zftLAoa6C+15lgaQ+M4f1GM8Lvs/Yq6VEzh81RMZknQJtrmtwS9j+Me7xudNqyiUUVV5V0/8XFog7M7EA==",
                                "ttl": 2347,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/62385",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 62385)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcFibspf7LbUHI2O77ApMKzyW4Ujmic2ncmFuAptCU5riLgHDtBKQgb/bVHIW0EtiLlJK7UMXTInkWKya8YpZliI4LpYzn2wEVHqR+p4XFPUsbTF5iShO9eHSGQeKxDdCE1uvm+KgowaTYZXer1CWkLU5dXgw5NJ8aJc+yH3d2SN",
                "ttl": 2347,
                "key_length": 1024,
                "key_tag": 62385,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/46672",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcUAm28CTpQ/EyWVjStctnLxuNhYXJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQdPLreAY06nGHDob73q8M6G4FhBpu++omg7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQtC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtNBFlMRhFEeXivMga65EVt7Rti8Dq0ehP9UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46KRG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRyC44xO4pIS1wunOlm8LO0D9W4dTE=",
                "ttl": 2347,
                "key_length": 2048,
                "key_tag": 46672,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/6363",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 6363)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcW2xlVorpxgdGPtoShZkmy+GZXlmz7VQqQIAbD7TvBAND+94nKd/LGB/wQdpqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvsSUpky4MFF45iFy/NiaZr6qWAXWoI6rlZNYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTsvesKUQDPNTihi34J",
                "ttl": 2347,
                "key_length": 1024,
                "key_tag": 6363,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/46672/2",
                    "description": "DS record(s) corresponding to DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                    "algorithm": 8,
                    "key_tag": 46672,
                    "digest_type": 2,
                    "digest": "AzndmbhrlrjkN5COmuo+tXj60N4hG9jPek/miF4KzdI=",
                    "ttl": 30924,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DS",
                        "description": "RRset for dnssec.works/DS",
                        "name": "dnssec.works.",
                        "ttl": 2124,
                        "type": "DS",
                        "rdata": [
                            "41779 8 2 a73a4215b94fd90c2e6b94bd0513c7a82c4a1e592fd686420573e611a1d29de1"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/6363",
                                "description": "RRSIG covering dnssec.works/DS",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 6363,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "OSMVJegb03XVAR3ljqkmFxYxPFAKsUVf4B+HvGV92HzgMLly25K5bhEYEDipP2jnEd1Dbct61DlVvZcH2fwRl6tPIF0+RyXeqYF/gY8kKs7DXPs5/bGxTgYd36mc6CtP71l4LCt4ZzqhmHeqj7e0acTChN70NaUWPOwg2gQdGv8=",
                                "ttl": 2124,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DNSKEY",
                        "description": "RRset for dnssec.works/DNSKEY",
                        "name": "dnssec.works.",
                        "ttl": 6324,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n 39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqu cszYfwIpgGZb3b+6k1Xn8x6h5lHLipLA QVOJLq3/RZYB8VG2U6L6tu5tsTADPzT2 9boRAXnV3/yPk6sO9WqQcpQXIRkMOpTo u6EozHeBVgSphSWK4CEPWbR8BAmuswzu glqp05EWcRqJ++MG4ur4C4GXy3lSPiCw jAL1eJNqDBjSzqqptYdshtO0lqzFM0RC 36RoCQ==",
                            "257 3 8 AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz 03z5pZwZWpMRJu33+GQLswgZJJX/iOTc jwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7 DkvqQAJyDTfjVXEyX/745e/5CCPAkVGn aZihj9jqichokDfWkAOJvGxqg9HdqsLm XH3a2GrxFfvwsdSPuBwQmSVzURIyZMMx RC+GH2B+ADGWxJNvrspS0lf9svfkrdMv G4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS /6iB8FLBKnltYtsXuveovKp9Dwq+xllq vUQTkRK90aUQEQa8G8ukecJbIliCrPJH 7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7E VDcgwskGj/NdfEHUuBdw+Vr9eHu8x6ao U/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lq VP2Xw6cpROGviS6Z"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/41779",
                                "description": "RRSIG covering dnssec.works/DNSKEY",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 41779,
                                "original_ttl": 7200,
                                "labels": 2,
                                "inception": "2026-09-07 15:59:12 UTC",
                                "expiration": "2026-09-17 16:00:28 UTC",
                                "signature": "UiFr9a4PqfiuNTxqRF6LQz+12ymilKZ4r2mEVuPQYPm2zTSgk8baidhR2o+Us6YoblPW1PYbLjXSPxHoNFSAZMzLOKN9aqRhowKxoePn8EbnG9EiesNG4RJl0BcHItihzj6x+lUwKpVEDJn6CoO7/bGGd+aNlp7ixaEWXyO+DaW3qKDRRIFnnjihdxMrrY7QSg619F0AEbl8BgOF7reEIAnmRKsd5lGbQ9YAdLZYZAW9UlzJwSZEiHZdkjyAuh4qgZ+1Nazd41qTlzicuxr961EHB71oe7tpudCRCuhIs/pjBP12glcVQW0xBg0Kkbpb98oejJ3zrOeylO4N+YjezuPe1rwqYv2ksKMhL6Kc4h7Zde+DRSdFaVnLWktOS05oHXcTMW/Jcn34nyoV5kLyotStyIe5P2rt2c54zpeZ01s=",
                                "ttl": 6324,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/63735",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 63735)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqucszYfwIpgGZb3b+6k1Xn8x6h5lHLipLAQVOJLq3/RZYB8VG2U6L6tu5tsTADPzT29boRAXnV3/yPk6sO9WqQcpQXIRkMOpTou6EozHeBVgSphSWK4CEPWbR8BAmuswzuglqp05EWcRqJ++MG4ur4C4GXy3lSPiCwjAL1eJNqDBjSzqqptYdshtO0lqzFM0RC36RoCQ==",
                "ttl": 6324,
                "key_length": 1536,
                "key_tag": 63735,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/41779",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz03z5pZwZWpMRJu33+GQLswgZJJX/iOTcjwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7DkvqQAJyDTfjVXEyX/745e/5CCPAkVGnaZihj9jqichokDfWkAOJvGxqg9HdqsLmXH3a2GrxFfvwsdSPuBwQmSVzURIyZMMxRC+GH2B+ADGWxJNvrspS0lf9svfkrdMvG4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS/6iB8FLBKnltYtsXuveovKp9Dwq+xllqvUQTkRK90aUQEQa8G8ukecJbIliCrPJH7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7EVDcgwskGj/NdfEHUuBdw+Vr9eHu8x6aoU/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lqVP2Xw6cpROGviS6Z",
                "ttl": 6324,
                "key_length": 2560,
                "key_tag": 41779,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/41779/2",
                    "description": "DS record(s) corresponding to DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                    "algorithm": 8,
                    "key_tag": 41779,
                    "digest_type": 2,
                    "digest": "pzpCFblP2Qwua5S9BRPHqCxKHlkv1oZCBXPmEaHSneE=",
                    "ttl": 2124,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "fail03.dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "fail03.dnssec.works./IN/A": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/A",
                        "description": "RRset for fail03.dnssec.works/A",
                        "name": "fail03.dnssec.works.",
                        "ttl": 3600,
                        "type": "A",
                        "rdata": [
                            "5.45.109.212"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail03.dnssec.works./8/8628",
                                "description": "RRSIG covering fail03.dnssec.works/A",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 8628,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "MYouSHouldNOTbeABLEtoREADaSIGNATURETJVpJxaXFn5vv4uwKgX3lY//zqY3xytuvRuQdyRe8og+iXepLPD01j8CyLpsdeMbUEVzCLYIGiBp+Om6CMIqD5yKillroyWasHereCSlNbD2L9n4Z6lM2UuCdURKuukV6Fp2ZCzBiOPAPSVaZO81iNv4+3YysGGpTJ6RTMMP1uRkTaVSs/PIpwZFA07M2g4qd3H45D/BpQxD+g/bx50fqCCdU/ELI",
                                "ttl": 3600,
                                "status": "INVALID_SIG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "errors": [
                                    {
                                        "description": "The cryptographic signature of the RRSIG RR does not properly validate.  See RFC 4035, Sec. 5.3.3.",
                                        "code": "SIGNATURE_INVALID"
                                    }
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set (however, this server appeared to respond legitimately to other queries with the CD flag cleared).  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail03.dnssec.works./IN/NS": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/NS",
                        "description": "RRset for fail03.dnssec.works/NS",
                        "name": "fail03.dnssec.works.",
                        "ttl": 3600,
                        "type": "NS",
                        "rdata": [
                            "ns2.myinfrastructure.org.",
                            "ns3.myinfrastructure.org."
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail03.dnssec.works./8/8628",
                                "description": "RRSIG covering fail03.dnssec.works/NS",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 8628,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "z2PElSsIGmqNLbHuqbJtSS1yyNo9TZprDO2HDa0NDcThhN8BzMD68exrkvdK3Fh0Q5jVmcQBc2GRwGOu2dQdumjjRlnQLGm3Ej7ac3QSyo18E+lGaM3T05+dAKhNwTVzL5oLckPu5wz48W3RcxSwMTyAvV0qgn9CCS1QY0x+04YFjwc5vGRRQg8kSbJ5COuxPFU7nBJMa12tQ9pAxuam7Z1SRIWg67fwzlj+fCcwf1BZCmEvGiIZIN0m0Q3km3lW",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/CNAME": {
                "nodata": [
                    {
                        "id": "fail03.dnssec.works./IN/CNAME",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail03.dnssec.works/CNAME",
                                "nsec": [
                                    {
                                        "id": "fail03.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail03.dnssec.works/NSEC",
                                        "name": "fail03.dnssec.works.",
                                        "ttl": 3600,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail03.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail03.dnssec.works./8/8628",
                                                "description": "RRSIG covering fail03.dnssec.works/NSEC",
                                                "signer": "fail03.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 8628,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "DCsJeUH+FIwg1kjTZ4ftw5e0ZB+khgDUMVkTYDdNXQeMc+HTFrzsqyRiwFJiThE59tX5EzgVJ6WFHsdEnJPUpoS5ylAbBRrRU+C7RzFobFsqJ/3VzracjAaBMSgToehEe0j1v2x1VWG4FZLpW0WzEJpvLK76lZPm9HWBb3iC9V/Bc5dPTFF6o9FvKWafXqCLZKv6Go2vdMSyruV3uiw/nUnGHYv1K2nPtTuQpw9n4jyhQYhVYNN42xHxeKeqRc7A",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail03.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail03.dnssec.works./IN/SOA",
                                "description": "RRset for fail03.dnssec.works/SOA",
                                "name": "fail03.dnssec.works.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 5 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail03.dnssec.works./8/8628",
                                        "description": "RRSIG covering fail03.dnssec.works/SOA",
                                        "signer": "fail03.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 8628,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "KNsypddHOw9kld7Ye3YRhz3PwGE0hr5iMS7B4Zk7b2eR8a+B5TGvdxkOaVitWuw982K/JrtcQvNC51Panmh/Y7elJIjFb3xdg19lrdY3XqTpU3q/CwlpaRTBxDiPLifqrXyi+YXN34FsM65uc53jz2N8PiMty9BDMMM9pI2VxLx/JxB7llhSE0IQeT1KSR8Fp8Ci+v50dCXfxFk3LoouDqi+jg2bPNGe5s4D5Zzr5sYTifnUaoXck84jXCrWSX+R",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/SOA": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/SOA",
                        "description": "RRset for fail03.dnssec.works/SOA",
                        "name": "fail03.dnssec.works.",
                        "ttl": 3600,
                        "type": "SOA",
                        "rdata": [
                            "ns2.myinfrastructure.org. hostmaster.strotmann.de. 5 86400 7200 3542400 3600"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_N",
                            "UDP_+_EDNS0_4096_D_NK",
                            "UDP_+_EDNS0_4096_D_NK_0x20",
                            "UDP_+_EDNS0_512_128_NK",
                            "UDP_+_EDNS0_512__O(100)NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail03.dnssec.works./8/8628",
                                "description": "RRSIG covering fail03.dnssec.works/SOA",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 8628,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "KNsypddHOw9kld7Ye3YRhz3PwGE0hr5iMS7B4Zk7b2eR8a+B5TGvdxkOaVitWuw982K/JrtcQvNC51Panmh/Y7elJIjFb3xdg19lrdY3XqTpU3q/CwlpaRTBxDiPLifqrXyi+YXN34FsM65uc53jz2N8PiMty9BDMMM9pI2VxLx/JxB7llhSE0IQeT1KSR8Fp8Ci+v50dCXfxFk3LoouDqi+jg2bPNGe5s4D5Zzr5sYTifnUaoXck84jXCrWSX+R",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_N",
                                    "UDP_+_EDNS0_4096_D_NK",
                                    "UDP_+_EDNS0_4096_D_NK_0x20"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "NO_COOKIE",
                                "response": "NO_COOKIE_OPT"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/MX": {
                "nodata": [
                    {
                        "id": "fail03.dnssec.works./IN/MX",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail03.dnssec.works/MX",
                                "nsec": [
                                    {
                                        "id": "fail03.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail03.dnssec.works/NSEC",
                                        "name": "fail03.dnssec.works.",
                                        "ttl": 3600,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail03.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail03.dnssec.works./8/8628",
                                                "description": "RRSIG covering fail03.dnssec.works/NSEC",
                                                "signer": "fail03.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 8628,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "DCsJeUH+FIwg1kjTZ4ftw5e0ZB+khgDUMVkTYDdNXQeMc+HTFrzsqyRiwFJiThE59tX5EzgVJ6WFHsdEnJPUpoS5ylAbBRrRU+C7RzFobFsqJ/3VzracjAaBMSgToehEe0j1v2x1VWG4FZLpW0WzEJpvLK76lZPm9HWBb3iC9V/Bc5dPTFF6o9FvKWafXqCLZKv6Go2vdMSyruV3uiw/nUnGHYv1K2nPtTuQpw9n4jyhQYhVYNN42xHxeKeqRc7A",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail03.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail03.dnssec.works./IN/SOA",
                                "description": "RRset for fail03.dnssec.works/SOA",
                                "name": "fail03.dnssec.works.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 5 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail03.dnssec.works./8/8628",
                                        "description": "RRSIG covering fail03.dnssec.works/SOA",
                                        "signer": "fail03.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 8628,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "KNsypddHOw9kld7Ye3YRhz3PwGE0hr5iMS7B4Zk7b2eR8a+B5TGvdxkOaVitWuw982K/JrtcQvNC51Panmh/Y7elJIjFb3xdg19lrdY3XqTpU3q/CwlpaRTBxDiPLifqrXyi+YXN34FsM65uc53jz2N8PiMty9BDMMM9pI2VxLx/JxB7llhSE0IQeT1KSR8Fp8Ci+v50dCXfxFk3LoouDqi+jg2bPNGe5s4D5Zzr5sYTifnUaoXck84jXCrWSX+R",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/TXT": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/TXT",
                        "description": "RRset for fail03.dnssec.works/TXT",
                        "name": "fail03.dnssec.works.",
                        "ttl": 3600,
                        "type": "TXT",
                        "rdata": [
                            "\\"Yes, this is also broken\\""
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail03.dnssec.works./8/8628",
                                "description": "RRSIG covering fail03.dnssec.works/TXT",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 8628,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "mHBEnv9Wc6+OeVhhgi8yC8jXIix9n7sm7eYalhy+YQHhzQuqJFe+5Sfvfrtr+gldxic8jqS8tSDcFNMX1e5IhqaWQFM6ftYQkZuZZ2iQy56glr/2QWZTzBXU6rD8Hwy1GIQfP8t9NecTtfaLvnKltU4sMfVlBXTLZnPsoJEIsaofilXz9amg33e3RIVjQj/viEa72i+CJ3zegtzhIXlMXpXuyROxdUqNkMaQPboaTIkRQruoC9NcdJw+Qsa9YzNf",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/AAAA": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/AAAA",
                        "description": "RRset for fail03.dnssec.works/AAAA",
                        "name": "fail03.dnssec.works.",
                        "ttl": 3600,
                        "type": "AAAA",
                        "rdata": [
                            "2a01:198:2b6:1000:203:2dff:fe29:8424"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail03.dnssec.works./8/8628",
                                "description": "RRSIG covering fail03.dnssec.works/AAAA",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 8628,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "uBMdaRrjxlXtjjnZPYdl8hxaZgprWIRDxnxUuQEj1Ryrdz3y4GbuZlmBQE+DRqoLTYSHFDMn4ef9YaTbtHfP8AxD8Lp+5uLjol+syR72POmKYJYZoulp3Q469rZAp1XCXyQ6rP+MF215WvJo7CKOgLAEKevquvtSeJD0IFTmCgGoMNjKu5YkjaBxIT0tWp8KhPLBfeVwiMcATRcYUNYIY7fz3tH2cTkMKRLqwR7FeowTj11d5dCHsoHJ2yzHmsqE",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/DS",
                        "description": "RRset for fail03.dnssec.works/DS",
                        "name": "fail03.dnssec.works.",
                        "ttl": 28,
                        "type": "DS",
                        "rdata": [
                            "4699 8 2 d16a0f1c5d63a2d406d5af31740c4b9648bc6cc97c42bab5cd06dcb71ccf6afa"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/63735",
                                "description": "RRSIG covering fail03.dnssec.works/DS",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 63735,
                                "original_ttl": 30,
                                "labels": 3,
                                "inception": "2026-09-09 09:25:31 UTC",
                                "expiration": "2026-09-19 10:04:06 UTC",
                                "signature": "BYrqcM1MskHef+Sq7/Ki150cQLRIrc3RIDwYneJuC2i9rZCObWiIvUS7hBL3jTgocjHsR6EGCPsVFKFFWnhy/YhhYPIb81Tt2Ybt5XJV7aTR5c6+VYwQuSHRXYPJwQ0TdmloWnA/4IO9Y+NGCBtkb+jJ560lxdBdIZdIHJOPWk/4g4KO6a3B5U1qlz6Hz7qec9Udhp6kR05uSS4YUSgTIcYHRyKC0xyBaCmzubFsg1MFu8XStBZgCLQfPPw89oEl",
                                "ttl": 28,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail03.dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "fail03.dnssec.works./IN/DNSKEY",
                        "description": "RRset for fail03.dnssec.works/DNSKEY",
                        "name": "fail03.dnssec.works.",
                        "ttl": 3600,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAc/vjdSmr71L1GCg3qQXMKvi3T9a FDogGaDLo8I//hts8uRpP5bsXc4F9Eq7 uOFEf3v+D+zV2wCSqZJ+NDbiKBN9xBYA 7GMljspwNOSXH+GMD85vPxZheKu4oDpR HFoncfS8bIawHCpneRzyLlTxvAcTEIk2 lOwYOviqx5EzpkpthTUM3bSYfGziL1K/ lmneDRubE6n5mmVvYWMiRYuj6zdXdX2M KVsAGwlbDQ8/eaPcycUrSSrCKEGCLYb4 glos6w==",
                            "257 3 8 AwEAAbJ0ypw2CPopxwChGGbezaHTTXSU IM+cPig7Nwhb8+CvjMXvUQMRZrrwWUdE IcEtQbpqIqLWXRl5FrpL9RjPQL/ijO8H VD7R7gYJ1S71A2odnIel9Odeu2VkEeaj 4Z4RZOYdwcw1bMGPK0y43A32Mxm9RCXC rAr7ErBYlTLhnsEeYaLnpB07XHrHxHWi oK0mWJ3IZdz9hbPv2o5U+QAv0f7Jwpwm jQzu6/jLQi17OarmfWG/S4OGpAKNKuc+ FoSHU+yy/VY4EuM3XhZvcvlvA93qGy43 wTEyxL1m72l3pTwhUb5puoUerI64ZvKM 6uLA6BddoCLxqVvH9SZ0pcVcQ4RIhxhX CYLf4A7j1CMzlYeyJDZlP1bFic6sf2TH sBdC+shv0KbmTlfzwYKN4cfCg4/8UYag APovDaXiviBhBy4V"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail03.dnssec.works./8/4699",
                                "description": "RRSIG covering fail03.dnssec.works/DNSKEY",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 4699,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "XPzYMhC/uOGaP5u/ebot055MFSYV5NH9Sv8VX2RbY3+LBXYwD4j3+rsQ6EK6ZKZ0qPJq4g69VqKoj71bdYvPUNAMBg+eGCcSjaop++b73CIxaOvB7S0OJcLDPnQc22YJjAQ1YrMSIZEZeyOAy9UtyNcNiC+rDfIQmc3jMx9ECnR9tpMlRT519iRXHTVz/N/mbCY2guRqoRl0xjleig7pDWci0xY5YyX0zKadxUDTGafIih8FtKwihZM+BS86XicRRDlvTMyHzkqVB4TGai5DricKsKCps+LpqyIfr/hqpwp7n+pJh3HEwzos3i892zjXlVZKcQV3t8fMWOOPqKltVQQLiapS3nGoC1/B0KVsukZeEgyoD65dmeU1Cg/DtTehIGW9BeALvtZC3jC/dMZ005H+v9PIDNx0PdbGSZ6fL9o=",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "id": "fail03.dnssec.works./8/8628",
                                "description": "RRSIG covering fail03.dnssec.works/DNSKEY",
                                "signer": "fail03.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 8628,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "sondr+/gfJM0tFnsdpqRCs2NU0l60d+ik4QZxL+eu9czRbNaBm8s5TGwLKOvwKzudvN7RdMqe1EexrHLU5TNDxYBdReWRHSV77MozGkgr9py096hrVzE8aNTcNfhTjnl5PLn/f+BgxTPQbd3KCqv5h2pmBAhieKJfJwPnElze3mJBd7AG8xjJaF89x7Sa+NsVfpgXZVbTr9gWru2L+3Go7aCSSSekURm06/AIe2706Ow+3OPji4gDwDydMq9Gzys",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "75dh2.cnz5d.fail03.dnssec.works./IN/A": {
                "nxdomain": [
                    {
                        "id": "75dh2.cnz5d.fail03.dnssec.works./IN/A",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving the non-existence (NXDOMAIN) of 75dh2.cnz5d.fail03.dnssec.works",
                                "nsec": [
                                    {
                                        "id": "fail03.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail03.dnssec.works/NSEC",
                                        "name": "fail03.dnssec.works.",
                                        "ttl": 3600,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail03.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail03.dnssec.works./8/8628",
                                                "description": "RRSIG covering fail03.dnssec.works/NSEC",
                                                "signer": "fail03.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 8628,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "DCsJeUH+FIwg1kjTZ4ftw5e0ZB+khgDUMVkTYDdNXQeMc+HTFrzsqyRiwFJiThE59tX5EzgVJ6WFHsdEnJPUpoS5ylAbBRrRU+C7RzFobFsqJ/3VzracjAaBMSgToehEe0j1v2x1VWG4FZLpW0WzEJpvLK76lZPm9HWBb3iC9V/Bc5dPTFF6o9FvKWafXqCLZKv6Go2vdMSyruV3uiw/nUnGHYv1K2nPtTuQpw9n4jyhQYhVYNN42xHxeKeqRc7A",
                                                "ttl": 3600,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_covering": {
                                    "covered_name": "75dh2.cnz5d.fail03.dnssec.works.",
                                    "nsec_owner": "fail03.dnssec.works.",
                                    "nsec_next": "why.fail03.dnssec.works."
                                },
                                "wildcard_covering": {
                                    "covered_name": "*.fail03.dnssec.works.",
                                    "nsec_owner": "fail03.dnssec.works.",
                                    "nsec_next": "why.fail03.dnssec.works."
                                },
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail03.dnssec.works./IN/SOA",
                                "description": "RRset for fail03.dnssec.works/SOA",
                                "name": "fail03.dnssec.works.",
                                "ttl": 3600,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 5 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail03.dnssec.works./8/8628",
                                        "description": "RRSIG covering fail03.dnssec.works/SOA",
                                        "signer": "fail03.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 8628,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "KNsypddHOw9kld7Ye3YRhz3PwGE0hr5iMS7B4Zk7b2eR8a+B5TGvdxkOaVitWuw982K/JrtcQvNC51Panmh/Y7elJIjFb3xdg19lrdY3XqTpU3q/CwlpaRTBxDiPLifqrXyi+YXN34FsM65uc53jz2N8PiMty9BDMMM9pI2VxLx/JxB7llhSE0IQeT1KSR8Fp8Ci+v50dCXfxFk3LoouDqi+jg2bPNGe5s4D5Zzr5sYTifnUaoXck84jXCrWSX+R",
                                        "ttl": 3600,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/8628",
                "description": "DNSKEY for fail03.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 8628)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAc/vjdSmr71L1GCg3qQXMKvi3T9aFDogGaDLo8I//hts8uRpP5bsXc4F9Eq7uOFEf3v+D+zV2wCSqZJ+NDbiKBN9xBYA7GMljspwNOSXH+GMD85vPxZheKu4oDpRHFoncfS8bIawHCpneRzyLlTxvAcTEIk2lOwYOviqx5EzpkpthTUM3bSYfGziL1K/lmneDRubE6n5mmVvYWMiRYuj6zdXdX2MKVsAGwlbDQ8/eaPcycUrSSrCKEGCLYb4glos6w==",
                "ttl": 3600,
                "key_length": 1536,
                "key_tag": 8628,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/4699",
                "description": "DNSKEY for fail03.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 4699)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAbJ0ypw2CPopxwChGGbezaHTTXSUIM+cPig7Nwhb8+CvjMXvUQMRZrrwWUdEIcEtQbpqIqLWXRl5FrpL9RjPQL/ijO8HVD7R7gYJ1S71A2odnIel9Odeu2VkEeaj4Z4RZOYdwcw1bMGPK0y43A32Mxm9RCXCrAr7ErBYlTLhnsEeYaLnpB07XHrHxHWioK0mWJ3IZdz9hbPv2o5U+QAv0f7JwpwmjQzu6/jLQi17OarmfWG/S4OGpAKNKuc+FoSHU+yy/VY4EuM3XhZvcvlvA93qGy43wTEyxL1m72l3pTwhUb5puoUerI64ZvKM6uLA6BddoCLxqVvH9SZ0pcVcQ4RIhxhXCYLf4A7j1CMzlYeyJDZlP1bFic6sf2THsBdC+shv0KbmTlfzwYKN4cfCg4/8UYagAPovDaXiviBhBy4V",
                "ttl": 3600,
                "key_length": 2560,
                "key_tag": 4699,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/4699/2",
                    "description": "DS record(s) corresponding to DNSKEY for fail03.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 4699)",
                    "algorithm": 8,
                    "key_tag": 4699,
                    "digest_type": 2,
                    "digest": "0WoPHF1jotQG1a8xdAxLlki8bMl8Qrq1zQbctxzPavo=",
                    "ttl": 28,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    }
}

'''
DNSVIZ_RESULT_FAIL04_DNSSEC_WORKS = '''
{
    ".": {
        "status": "NOERROR",
        "queries": {
            "./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "./IN/DNSKEY",
                        "description": "RRset for ./DNSKEY",
                        "name": ".",
                        "ttl": 41171,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1 cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH /Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAW uEaEmYJ+GQPiwVVfstGwSA1McfFJUttT gq2Huu74KARhtA8wPo/N3XcyYQtNhz+q CM5NBb3ecx/naw6sYab9LxS6f2cU0q03 ++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV +tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI 34g1XVYrNlsCCTmNvFQIfzW5STFQFsQp izczyFn9r3LzSxxPCNwdlCG84bER0Bmd wqbF6Tanv+FxMOavrahkj4wIy5k=",
                            "257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexT BAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq 7HrxRixHlFlExOLAJr5emLvN7SWXgnLh 4+B5xQlNVz8Og8kvArMtNROxVQuCaSnI DdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLr jyBxWezF0jLHwVN8efS3rCj/EWgvIWgb 9tarpVUDK/b58Da+sqqls3eNbuv7pr+e oZG+SrDK6nWeL3c6H5Apxz7LjVc1uTId sIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6 +cn8HFRm+2hM8AnXGXws9555KrUB5qih ylGa8subX2Nn6UwNR1AkUTV74bU=",
                            "257 3 8 AwEAAa96jeuknZlaeSrvyAJj6ZHv28hh OKkx3rLGXVaC6rXTsDc449/cidltpkyG wCJNnOAlFNKF2jBosZBU5eeHspaQWOmO ElZsjICMQMC3aeHbGiShvZsx4wMYSjH8 e7Vrhbu6irwCzVBApESjbUdpWWmEnhat hWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/ dL/q8PkcRU5oUKEpUge71M3ej2/7CPqp dVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGO HOijtzN+u1TQNatX2XBuzZNQ1K+s2CXk PIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2 vaF18UYH9Z9GNUUeayffKC73PYc="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/20326",
                                "description": "RRSIG covering ./DNSKEY",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 20326,
                                "original_ttl": 172800,
                                "labels": 0,
                                "inception": "2026-08-30 00:00:00 UTC",
                                "expiration": "2026-09-20 00:00:00 UTC",
                                "signature": "PvfCYsLIvqwE52D32Fx+zL43nm8ojP/W3MbsbUu4IsBqewjFRvAv00Mp2ehX2IyjRUV2fhtHPFzL3G0PK9GucRv7Ab97RauaOiVJnAqqUjELQR4HedSNVnprjF8UUmRiXPOTXAD/WEWLAk9MOOcwF+xKeB4f8spcLMIVDA9r32afCpu2lhs/3rwDD687GCz2HN5y4/Ew5Wi8ZSD3TMtbaSoGOb73Zpzw0XqBk9PqBVEZPcR2bZkgPRQZRYz8Pwga658J1hhw6qn3eocf4WluAldJGd2wYvXLUrwdZESnYac0aq8OY2t3Z2MYoX1JnLQttItxyltVQIv8AoQnUMet/w==",
                                "ttl": 41171,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/38696",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 38696)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=",
                "ttl": 41171,
                "key_length": 2048,
                "key_tag": 38696,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/57780",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 57780)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeCYD6Z7WWKVLeuWgowKP+3g+Gs1cnLKq7a3CaQxQpv8bfuFVI0WnG33qaSH/Mw9IBgifrdzf4XY/DQLnyBJ9MfaOyAWuEaEmYJ+GQPiwVVfstGwSA1McfFJUttTgq2Huu74KARhtA8wPo/N3XcyYQtNhz+qCM5NBb3ecx/naw6sYab9LxS6f2cU0q03++BP5Ks0Uef8WJCa/1izCYE+vMkwoltV+tENa3hpXiZ7jle/xdgaZrPi5ZGmyLVI34g1XVYrNlsCCTmNvFQIfzW5STFQFsQpizczyFn9r3LzSxxPCNwdlCG84bER0BmdwqbF6Tanv+FxMOavrahkj4wIy5k=",
                "ttl": 41171,
                "key_length": 2048,
                "key_tag": 57780,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/20326",
                "description": "DNSKEY for . (algorithm 8 (RSA/SHA-256), key tag 20326)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
                "ttl": 41171,
                "key_length": 2048,
                "key_tag": 20326,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ]
    },
    "works.": {
        "status": "NOERROR",
        "queries": {
            "works./IN/DS": {
                "answer": [
                    {
                        "id": "works./IN/DS",
                        "description": "RRset for works/DS",
                        "name": "works.",
                        "ttl": 29951,
                        "type": "DS",
                        "rdata": [
                            "46672 8 2 0339dd99b86b96b8e437908e9aea3eb578fad0de211bd8cf7a4fe6885e0acdd2"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "./8/57780",
                                "description": "RRSIG covering works/DS",
                                "signer": ".",
                                "algorithm": 8,
                                "key_tag": 57780,
                                "original_ttl": 86400,
                                "labels": 1,
                                "inception": "2026-09-08 19:00:00 UTC",
                                "expiration": "2026-09-21 20:00:00 UTC",
                                "signature": "HJ4xY2Dw8pR0s/RsS4X7DUdbQbI+YW+ZJOGN0Z8Pp2Ck6gx/dF1jGJh29J5f47+jH5+nV1Xxxm32ShwJxYJZkPUv4RZnLdkJ4zn3pE8KVwoD8lQSEp/KjK2Ep5OjXSA7nj9Zc13xoC39NaVvb+BWnKAAt++Ejy4iGiAGQI1czYNFvEmEz8gNphO3GJC/fioXvkDu+q7eueUW//VsJskGpZQtq14F02Zz7GirNggLgiWKzcuY/F7h1vmFfXmQmrljqD5h7gS2s2zVkjMGuTmfy66vIldeIOupODvatnrlswvkLYJZAVSLOjQ+3Mhn4hqZUssVGMlL9Wql4m1IF0LReA==",
                                "ttl": 29951,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "works./IN/DNSKEY",
                        "description": "RRset for works/DNSKEY",
                        "name": "works.",
                        "ttl": 1374,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAcFibspf7LbUHI2O77ApMKzyW4Uj mic2ncmFuAptCU5riLgHDtBKQgb/bVHI W0EtiLlJK7UMXTInkWKya8YpZliI4LpY zn2wEVHqR+p4XFPUsbTF5iShO9eHSGQe KxDdCE1uvm+KgowaTYZXer1CWkLU5dXg w5NJ8aJc+yH3d2SN",
                            "256 3 8 AwEAAcW2xlVorpxgdGPtoShZkmy+GZXl mz7VQqQIAbD7TvBAND+94nKd/LGB/wQd pqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvs SUpky4MFF45iFy/NiaZr6qWAXWoI6rlZ NYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTs vesKUQDPNTihi34J",
                            "257 3 8 AwEAAcUAm28CTpQ/EyWVjStctnLxuNhY XJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2 D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQ dPLreAY06nGHDob73q8M6G4FhBpu++om g7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQ tC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka 1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtN BFlMRhFEeXivMga65EVt7Rti8Dq0ehP9 UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46K RG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRy C44xO4pIS1wunOlm8LO0D9W4dTE="
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/46672",
                                "description": "RRSIG covering works/DNSKEY",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 46672,
                                "original_ttl": 3600,
                                "labels": 1,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "CAblYJ3CQwNY9RPbH4qC2o5p1uT+6SmIEoN2g4VL4pljc4sqbiNiXujMQi02QFXopGySdUbcM8MvQLcRtKUu+PdR0eJ2UHtVzPqMEuCk6XKxke0aXejLvo6BGFNKWA80T2Ka6gE8tvsXCpKDiEuWJ+HryJroI3oay2/QVdMRL+Dj75cx5/bdnJGl7/KS9FLcaibRMwfNjvpHwhSz+ZLwWIyaiBvKTvC84lks/F0+P11UTnUcA9/mDwLij5a4S0q2vr8M5zftLAoa6C+15lgaQ+M4f1GM8Lvs/Yq6VEzh81RMZknQJtrmtwS9j+Me7xudNqyiUUVV5V0/8XFog7M7EA==",
                                "ttl": 1374,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/62385",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 62385)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcFibspf7LbUHI2O77ApMKzyW4Ujmic2ncmFuAptCU5riLgHDtBKQgb/bVHIW0EtiLlJK7UMXTInkWKya8YpZliI4LpYzn2wEVHqR+p4XFPUsbTF5iShO9eHSGQeKxDdCE1uvm+KgowaTYZXer1CWkLU5dXgw5NJ8aJc+yH3d2SN",
                "ttl": 1374,
                "key_length": 1024,
                "key_tag": 62385,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/46672",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcUAm28CTpQ/EyWVjStctnLxuNhYXJuRfryyXZHUgO0WnvOX5tfWyt/c2fi2D8g2n4eIkyw8B8IUb/qQP/d8jwTaOtCQdPLreAY06nGHDob73q8M6G4FhBpu++omg7DghB5aTF+wZQfLmjOahp3oxGZ/K8KQtC+3cwuMvFckRzR+Zg2IW/zKLTPYb3Ka1PZrs3ar+AUzDGFr8Ev/D8F+5JHBzAtNBFlMRhFEeXivMga65EVt7Rti8Dq0ehP9UWsEEGgeu9WA+QbnWGhNMNlS8MaCr46KRG1XpF0EE2drZS5Bx0ci8vpe9Ew2gsRyC44xO4pIS1wunOlm8LO0D9W4dTE=",
                "ttl": 1374,
                "key_length": 2048,
                "key_tag": 46672,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/6363",
                "description": "DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 6363)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcW2xlVorpxgdGPtoShZkmy+GZXlmz7VQqQIAbD7TvBAND+94nKd/LGB/wQdpqQg7MHzwD3rPO3x/YL9pRSWw2wrRnvsSUpky4MFF45iFy/NiaZr6qWAXWoI6rlZNYxNKkZRaXdOb4qCC2wTTKBZmZZNFyTsvesKUQDPNTihi34J",
                "ttl": 1374,
                "key_length": 1024,
                "key_tag": 6363,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/46672/2",
                    "description": "DS record(s) corresponding to DNSKEY for works (algorithm 8 (RSA/SHA-256), key tag 46672)",
                    "algorithm": 8,
                    "key_tag": 46672,
                    "digest_type": 2,
                    "digest": "AzndmbhrlrjkN5COmuo+tXj60N4hG9jPek/miF4KzdI=",
                    "ttl": 29951,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DS",
                        "description": "RRset for dnssec.works/DS",
                        "name": "dnssec.works.",
                        "ttl": 1151,
                        "type": "DS",
                        "rdata": [
                            "41779 8 2 a73a4215b94fd90c2e6b94bd0513c7a82c4a1e592fd686420573e611a1d29de1"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "works./8/6363",
                                "description": "RRSIG covering dnssec.works/DS",
                                "signer": "works.",
                                "algorithm": 8,
                                "key_tag": 6363,
                                "original_ttl": 3600,
                                "labels": 2,
                                "inception": "2026-09-01 14:20:04 UTC",
                                "expiration": "2026-09-22 15:20:04 UTC",
                                "signature": "OSMVJegb03XVAR3ljqkmFxYxPFAKsUVf4B+HvGV92HzgMLly25K5bhEYEDipP2jnEd1Dbct61DlVvZcH2fwRl6tPIF0+RyXeqYF/gY8kKs7DXPs5/bGxTgYd36mc6CtP71l4LCt4ZzqhmHeqj7e0acTChN70NaUWPOwg2gQdGv8=",
                                "ttl": 1151,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "dnssec.works./IN/DNSKEY",
                        "description": "RRset for dnssec.works/DNSKEY",
                        "name": "dnssec.works.",
                        "ttl": 5351,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n 39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqu cszYfwIpgGZb3b+6k1Xn8x6h5lHLipLA QVOJLq3/RZYB8VG2U6L6tu5tsTADPzT2 9boRAXnV3/yPk6sO9WqQcpQXIRkMOpTo u6EozHeBVgSphSWK4CEPWbR8BAmuswzu glqp05EWcRqJ++MG4ur4C4GXy3lSPiCw jAL1eJNqDBjSzqqptYdshtO0lqzFM0RC 36RoCQ==",
                            "257 3 8 AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz 03z5pZwZWpMRJu33+GQLswgZJJX/iOTc jwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7 DkvqQAJyDTfjVXEyX/745e/5CCPAkVGn aZihj9jqichokDfWkAOJvGxqg9HdqsLm XH3a2GrxFfvwsdSPuBwQmSVzURIyZMMx RC+GH2B+ADGWxJNvrspS0lf9svfkrdMv G4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS /6iB8FLBKnltYtsXuveovKp9Dwq+xllq vUQTkRK90aUQEQa8G8ukecJbIliCrPJH 7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7E VDcgwskGj/NdfEHUuBdw+Vr9eHu8x6ao U/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lq VP2Xw6cpROGviS6Z"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/41779",
                                "description": "RRSIG covering dnssec.works/DNSKEY",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 41779,
                                "original_ttl": 7200,
                                "labels": 2,
                                "inception": "2026-09-07 15:59:12 UTC",
                                "expiration": "2026-09-17 16:00:28 UTC",
                                "signature": "UiFr9a4PqfiuNTxqRF6LQz+12ymilKZ4r2mEVuPQYPm2zTSgk8baidhR2o+Us6YoblPW1PYbLjXSPxHoNFSAZMzLOKN9aqRhowKxoePn8EbnG9EiesNG4RJl0BcHItihzj6x+lUwKpVEDJn6CoO7/bGGd+aNlp7ixaEWXyO+DaW3qKDRRIFnnjihdxMrrY7QSg619F0AEbl8BgOF7reEIAnmRKsd5lGbQ9YAdLZYZAW9UlzJwSZEiHZdkjyAuh4qgZ+1Nazd41qTlzicuxr961EHB71oe7tpudCRCuhIs/pjBP12glcVQW0xBg0Kkbpb98oejJ3zrOeylO4N+YjezuPe1rwqYv2ksKMhL6Kc4h7Zde+DRSdFaVnLWktOS05oHXcTMW/Jcn34nyoV5kLyotStyIe5P2rt2c54zpeZ01s=",
                                "ttl": 5351,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "VALID_SERVER_COOKIE",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/63735",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 63735)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAavabLV/hlCxC5ehKxZK5I7NHN8n39Lu4RqJTWU/yQhAaeajvc8QQjO+sEqucszYfwIpgGZb3b+6k1Xn8x6h5lHLipLAQVOJLq3/RZYB8VG2U6L6tu5tsTADPzT29boRAXnV3/yPk6sO9WqQcpQXIRkMOpTou6EozHeBVgSphSWK4CEPWbR8BAmuswzuglqp05EWcRqJ++MG4ur4C4GXy3lSPiCwjAL1eJNqDBjSzqqptYdshtO0lqzFM0RC36RoCQ==",
                "ttl": 5351,
                "key_length": 1536,
                "key_tag": 63735,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/41779",
                "description": "DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAa+YwrBlCwfJzwmsSK87hKFAm+yz03z5pZwZWpMRJu33+GQLswgZJJX/iOTcjwHdpQXvbAHwNhLtTJ1Pp46b55Q8+zH7DkvqQAJyDTfjVXEyX/745e/5CCPAkVGnaZihj9jqichokDfWkAOJvGxqg9HdqsLmXH3a2GrxFfvwsdSPuBwQmSVzURIyZMMxRC+GH2B+ADGWxJNvrspS0lf9svfkrdMvG4hjLhwNViDSjdx9yb4yRH/+TgvTAkYS/6iB8FLBKnltYtsXuveovKp9Dwq+xllqvUQTkRK90aUQEQa8G8ukecJbIliCrPJH7JK2IaDX8ezoYZ4QMZPc2y/K8FHK0G7EVDcgwskGj/NdfEHUuBdw+Vr9eHu8x6aoU/tnTRI7qI2HmCUqcVLSEGJAmKu4A7lqVP2Xw6cpROGviS6Z",
                "ttl": 5351,
                "key_length": 2560,
                "key_tag": 41779,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "UDP_+_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "8/41779/2",
                    "description": "DS record(s) corresponding to DNSKEY for dnssec.works (algorithm 8 (RSA/SHA-256), key tag 41779)",
                    "algorithm": 8,
                    "key_tag": 41779,
                    "digest_type": 2,
                    "digest": "pzpCFblP2Qwua5S9BRPHqCxKHlkv1oZCBXPmEaHSneE=",
                    "ttl": 1151,
                    "status": "VALID",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "SECURE"
        }
    },
    "fail04.dnssec.works.": {
        "status": "NOERROR",
        "queries": {
            "fail04.dnssec.works./IN/A": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/A",
                        "description": "RRset for fail04.dnssec.works/A",
                        "name": "fail04.dnssec.works.",
                        "ttl": 3600,
                        "type": "A",
                        "rdata": [
                            "5.45.109.212"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail04.dnssec.works./8/44118",
                                "description": "RRSIG covering fail04.dnssec.works/A",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 44118,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "JORMpmixBMleoa6Kql1JtY122y9EPHEJV7An2dVIGjlLAn3H29kRz6hznplV4QVCOWo8Oe4puWK1ZqXN4Zp6ozBBxMjSWUj691ehgh/4aLa+O2KBom0Zelpw8FAwsyxiFruowu8VOt2WtC96pOq6DfioXboaHmvSga0cpwXN64OorS6yVTncxRvKUbpvnkvDj5j7cLEMjlTh7ey04muQKKzNMePOKu6dnbitp7RQ3qNiDdugJ2gQ3c7+YIcmCIo+",
                                "ttl": 3600,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set (however, this server appeared to respond legitimately to other queries with the CD flag cleared).  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail04.dnssec.works./IN/NS": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/NS",
                        "description": "RRset for fail04.dnssec.works/NS",
                        "name": "fail04.dnssec.works.",
                        "ttl": 3597,
                        "type": "NS",
                        "rdata": [
                            "ns2.myinfrastructure.org.",
                            "ns3.myinfrastructure.org."
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail04.dnssec.works./8/44118",
                                "description": "RRSIG covering fail04.dnssec.works/NS",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 44118,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "V44UC13bOBJc1ANgW7LL1jQPW0tTIOKjOptY4sNBIuDIEOxDXdmmVKGO1bz9Ewe/7p54PKSRiSAsLMgZ9/WkILumxFayo9yg7D+Hsv+WgPY3oSZeXcMuS/+1R1bTsRJ+sapfiMVzTj4pKx8l0CQl0ieTQ7afhNPMQgt3zqHAxq4gfKFdobCMCUkmDcM2THwXCUDTdVqe5ii6mDUrOtA9fWnNKG92gVQbyw4HaGNU2HP69ifJy1zkx8LBpNtYpdWw",
                                "ttl": 3597,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set (however, this server appeared to respond legitimately to other queries with the CD flag cleared).  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail04.dnssec.works./IN/CNAME": {
                "nodata": [
                    {
                        "id": "fail04.dnssec.works./IN/CNAME",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail04.dnssec.works/CNAME",
                                "nsec": [
                                    {
                                        "id": "fail04.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail04.dnssec.works/NSEC",
                                        "name": "fail04.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail04.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail04.dnssec.works./8/44118",
                                                "description": "RRSIG covering fail04.dnssec.works/NSEC",
                                                "signer": "fail04.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 44118,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "h7vX5B8St9vzfGLhjsNvnG48utmR2SWhkvOoopt6y73M/wbjMhfMXFNHzFJyoEdLXEg4w2uFcdbS4DCydnrxLYQ55e0BCK/tCeBv+KnkpKU+IZIPw6SPp3nYNKBFqGTXyIGxY5UqyI0aAuCqQp6jf59bzaHQJZvsEvJi5Uap+iRIoir0AEItXoeppxGiQ9L75ZIFwESl95TmI17dy5e7tnBRS8PH+q/3nggMDLgAywHqFlwJk2zrt0V2/TbLG+xZ",
                                                "ttl": 3598,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ],
                                        "errors": [
                                            {
                                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail04.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail04.dnssec.works./IN/SOA",
                                "description": "RRset for fail04.dnssec.works/SOA",
                                "name": "fail04.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 17 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail04.dnssec.works./8/44118",
                                        "description": "RRSIG covering fail04.dnssec.works/SOA",
                                        "signer": "fail04.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 44118,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "C+eQdjrQMIJRZRdO3nNVEpFAVWt9/58cSOOSXBQFRlj+3e2M/+1h1qds+0SPtJv+lsYAjDbEAKrSsoc3jyqMMjyW71DWm+K2EMz/m3U1l/RvWQDQ7vXuECsBcF2uXkKYpUbIPHQooRG/I9mDcBy6xJx3IBuEt6I3JCqRS9Z5z8ZgJyTHJJqkFycl2tP8c/22luHphN9yTfftL7qAEZkXJDhaqOSadgdvzFlsGZj6rVyLK1cmc9EMNrPxUnOWWjAH",
                                        "ttl": 3598,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ],
                                "errors": [
                                    {
                                        "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                        "code": "MISSING_RRSIG_FOR_ALG_DS",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail04.dnssec.works./IN/SOA": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/SOA",
                        "description": "RRset for fail04.dnssec.works/SOA",
                        "name": "fail04.dnssec.works.",
                        "ttl": 3598,
                        "type": "SOA",
                        "rdata": [
                            "ns2.myinfrastructure.org. hostmaster.strotmann.de. 17 86400 7200 3542400 3600"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+C_EDNS0_4096_D_N",
                            "UDP_+C_EDNS0_4096_D_NK",
                            "UDP_+C_EDNS0_4096_D_NK_0x20",
                            "UDP_+C_EDNS0_512_128_NK",
                            "UDP_+C_EDNS0_512__O(100)NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail04.dnssec.works./8/44118",
                                "description": "RRSIG covering fail04.dnssec.works/SOA",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 44118,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "C+eQdjrQMIJRZRdO3nNVEpFAVWt9/58cSOOSXBQFRlj+3e2M/+1h1qds+0SPtJv+lsYAjDbEAKrSsoc3jyqMMjyW71DWm+K2EMz/m3U1l/RvWQDQ7vXuECsBcF2uXkKYpUbIPHQooRG/I9mDcBy6xJx3IBuEt6I3JCqRS9Z5z8ZgJyTHJJqkFycl2tP8c/22luHphN9yTfftL7qAEZkXJDhaqOSadgdvzFlsGZj6rVyLK1cmc9EMNrPxUnOWWjAH",
                                "ttl": 3598,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_N",
                                    "UDP_+C_EDNS0_4096_D_NK",
                                    "UDP_+C_EDNS0_4096_D_NK_0x20"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "NO_COOKIE",
                                "response": "NO_COOKIE_OPT"
                            }
                        },
                        "errors": [
                            {
                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_N",
                                    "UDP_+C_EDNS0_4096_D_NK",
                                    "UDP_+C_EDNS0_4096_D_NK_0x20"
                                ]
                            },
                            {
                                "description": "The response had an invalid RCODE (SERVFAIL) until the CD flag was set.  See RFC 1035, Sec. 4.1.1.",
                                "code": "ERROR_WITHOUT_REQUEST_FLAG",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "TCP_+_EDNS0_4096_D_N"
                                ]
                            },
                            {
                                "description": "DNSSEC was effectively downgraded because the response had an invalid RCODE (SERVFAIL) with EDNS enabled.  See RFC 6891, Sec. 7, RFC 2671, Sec. 5.3.",
                                "code": "DNSSEC_DOWNGRADE_EDNS_DISABLED",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_N"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail04.dnssec.works./IN/MX": {
                "nodata": [
                    {
                        "id": "fail04.dnssec.works./IN/MX",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving non-existence (NODATA) of fail04.dnssec.works/MX",
                                "nsec": [
                                    {
                                        "id": "fail04.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail04.dnssec.works/NSEC",
                                        "name": "fail04.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail04.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail04.dnssec.works./8/44118",
                                                "description": "RRSIG covering fail04.dnssec.works/NSEC",
                                                "signer": "fail04.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 44118,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "h7vX5B8St9vzfGLhjsNvnG48utmR2SWhkvOoopt6y73M/wbjMhfMXFNHzFJyoEdLXEg4w2uFcdbS4DCydnrxLYQ55e0BCK/tCeBv+KnkpKU+IZIPw6SPp3nYNKBFqGTXyIGxY5UqyI0aAuCqQp6jf59bzaHQJZvsEvJi5Uap+iRIoir0AEItXoeppxGiQ9L75ZIFwESl95TmI17dy5e7tnBRS8PH+q/3nggMDLgAywHqFlwJk2zrt0V2/TbLG+xZ",
                                                "ttl": 3598,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ],
                                        "errors": [
                                            {
                                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_nsec_match": "fail04.dnssec.works.",
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail04.dnssec.works./IN/SOA",
                                "description": "RRset for fail04.dnssec.works/SOA",
                                "name": "fail04.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 17 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail04.dnssec.works./8/44118",
                                        "description": "RRSIG covering fail04.dnssec.works/SOA",
                                        "signer": "fail04.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 44118,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "C+eQdjrQMIJRZRdO3nNVEpFAVWt9/58cSOOSXBQFRlj+3e2M/+1h1qds+0SPtJv+lsYAjDbEAKrSsoc3jyqMMjyW71DWm+K2EMz/m3U1l/RvWQDQ7vXuECsBcF2uXkKYpUbIPHQooRG/I9mDcBy6xJx3IBuEt6I3JCqRS9Z5z8ZgJyTHJJqkFycl2tP8c/22luHphN9yTfftL7qAEZkXJDhaqOSadgdvzFlsGZj6rVyLK1cmc9EMNrPxUnOWWjAH",
                                        "ttl": 3598,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ],
                                "errors": [
                                    {
                                        "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                        "code": "MISSING_RRSIG_FOR_ALG_DS",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail04.dnssec.works./IN/TXT": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/TXT",
                        "description": "RRset for fail04.dnssec.works/TXT",
                        "name": "fail04.dnssec.works.",
                        "ttl": 3598,
                        "type": "TXT",
                        "rdata": [
                            "\\"strange, this is broken too\\""
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail04.dnssec.works./8/44118",
                                "description": "RRSIG covering fail04.dnssec.works/TXT",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 44118,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "FtwGiG3Z2s6x326sSq2GvR4g2ATNBPSb9wNuVazNu47geBDLN8yNLyb6vyh+tLQDSoUGghic4Zhyg6bjLMpT6zcCVV2UelMGEKsRt6Zyxrb261gwGi+J4YYdhNKEbUi+16hmRmMpp0pIuCPcL2FFTVii7G3vo6QNk/LHtftRktob5cHrKv3CRUAI4AayJeY2kDf4NwTZuCSvngGPJfoKov52lgs0BnymXIVSh10aVSyl/U+pagZYttw2uWi+rcwi",
                                "ttl": 3598,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail04.dnssec.works./IN/AAAA": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/AAAA",
                        "description": "RRset for fail04.dnssec.works/AAAA",
                        "name": "fail04.dnssec.works.",
                        "ttl": 3598,
                        "type": "AAAA",
                        "rdata": [
                            "2a01:198:2b6:1000:203:2dff:fe29:8424"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail04.dnssec.works./8/44118",
                                "description": "RRSIG covering fail04.dnssec.works/AAAA",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 44118,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "Fj/t7tnHVAb/DqV5OkHkkH2eDNqY7hdRYukI8LvY50Ux3A5xD9fEZOlgym19PKukZJV7tTR+H6iDwo5TfKTcNzwhzsr59T/2DjN8WqCch2JTD2lDBJi37oCA/lVLRq9E+fnL+cn+YS/yzQlsyJh8YN42aT9Nu5j34u2k4Z31NN5VOb3vSNBXM5bz+e5F8MZBYj0qr9Drh9T22r5Jr9+Pm8eRIl70vZc8flSrvt4RJ4jHhtbnujv50BYQ8HFNjrHa",
                                "ttl": 3598,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "fail04.dnssec.works./IN/DS": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/DS",
                        "description": "RRset for fail04.dnssec.works/DS",
                        "name": "fail04.dnssec.works.",
                        "ttl": 57,
                        "type": "DS",
                        "rdata": [
                            "6502 7 2 a587394a0be247627e3bc5ca5a985ba7f6611455446471cea1ee91197dd268c1"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "dnssec.works./8/63735",
                                "description": "RRSIG covering fail04.dnssec.works/DS",
                                "signer": "dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 63735,
                                "original_ttl": 60,
                                "labels": 3,
                                "inception": "2026-09-09 09:25:31 UTC",
                                "expiration": "2026-09-19 10:04:06 UTC",
                                "signature": "BrFo1zSX0dYtYBzxo4395bekKoQt55UvzEfKnwWk2hyGNeAuHTWEOzzRHqp2gm8c4Sv1lPs5R9513+c+HCCPG6sYmqTcYQ2mF8Grr17Ma5QMKf+TvHRgFa5khhYvB3cC/vTWBAPb5hPs5TWPU2t6I9bjWQ3VElLhdtPw9qTKbgEd56UFjnbcbXzgQBEFFMgIbBH6JuSbgaoq5Fu19CSOPZYb/z/HMYayaUGrpYPqxNY97+BN3JJIecu4SldVnId1",
                                "ttl": 57,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            },
            "fail04.dnssec.works./IN/DNSKEY": {
                "answer": [
                    {
                        "id": "fail04.dnssec.works./IN/DNSKEY",
                        "description": "RRset for fail04.dnssec.works/DNSKEY",
                        "name": "fail04.dnssec.works.",
                        "ttl": 3598,
                        "type": "DNSKEY",
                        "rdata": [
                            "256 3 8 AwEAAcgPNRU1zeVIZG9Kwa0SsMSDnMa8 H18qxU0ZW1QEFveujkRdWO6L7/iokazZ WVMeKmv4pGGyMOKTmgDl96yzEjgbtjCo Hrd4mql6EFoQulbWkz/AXDgj0TeeX186 3jGHJuEDiQQhnKPSBNx1vJ7tJfexAZV0 UMU/lglmySKn4Nr9mVmg73dzWPBbvE+N krBaH9+7/S+RNjBEq4r73LBwBVLZgnVl nL3Ti4xyVfizq319RagEoFjuUeLGSoI4 Vk5nFw==",
                            "257 3 8 AwEAAeixmnzdleIbyGfP9k52kFjo0qzR 2AbE8icgZrI8RV2Zc1wf4t8qQsv3Htce RLwqldsHtlMGTdrKMo+DbzbiIcfxOx7I mago4pkjmlnvAT6wi4zdEF39/hv8miIS h/ddI+t1pa3OOqONA4CyUckcS6Q0qLVW BXetXIVu/TtF06VkAcc7vr2Ml4Gt5XAK 4TMBVdrtNQxc/ARY+X9Ms2GvBATs77Nv fuXFNFifZA20P0lJw/CFW/t+8ImHGtwE hKfThueNozeJ/eMn0mGjvrtyGJ2ww2DB sGL+fAPr+ODAntoJjo/ftZREJOsvZ7Vv G9QTvD0XXeNwMXc18P59QtZVkyJ062Sr cRxg5KpAf3sbkwE0snVOqGuXbEjX+6Cs VSrB8BqhFV4RxCxSVwziZSaoUHne4d9o NuOeh00aD9TOKRgb"
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "TCP_+C_EDNS0_4096_D_NK"
                        ],
                        "rrsig": [
                            {
                                "id": "fail04.dnssec.works./8/9127",
                                "description": "RRSIG covering fail04.dnssec.works/DNSKEY",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 9127,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "Xwu1JrNKiVNzc0ptUggRLJMaEUHCqc9sSQOAxPIA0tJ51XB1a0iFstI80pK8TToJ26+knPSY7UjX38i2tXSxNyhhYkk3zSJRKhTqJ4btpRNnvLF668bAzHWCye3zEQGhNHf4h/4wIjFBYMkJnb3uLxlgQTYWbMnEoWwALsl0bRDhGnCe0bYJTz+o1rvlZ9PP2YVkMILyelfRYcqmmf6YyGKHdwsF6oe83USkSWcOpbr8FfAY0W/s6Q+ifiVlqlespYLQISmIXLWzQgs41ZtasPGXyQX/+pEh2uIlu24vT6zXibPl5MLep+j1fBQ2EZLt0DpfEAK4dAL+7Jkp1Mb5deJX3O4IgJtQsTpMC2JSqbGtfizMIrxz9W5oDOH7aN0V836B55pPfyF4eOX/h0URbBgm06XbcvnzcTfUksdvbLI=",
                                "ttl": 3598,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_NK"
                                ]
                            },
                            {
                                "id": "fail04.dnssec.works./8/44118",
                                "description": "RRSIG covering fail04.dnssec.works/DNSKEY",
                                "signer": "fail04.dnssec.works.",
                                "algorithm": 8,
                                "key_tag": 44118,
                                "original_ttl": 3600,
                                "labels": 3,
                                "inception": "2021-01-01 00:00:00 UTC",
                                "expiration": "2070-01-01 00:00:00 UTC",
                                "signature": "ZRL2wBsWtDpJHlHrsVbbrs2NaW2P1OTwzUk6gUC+06jjiVscJdPxVJh89PpBGIn8KAq/tGxfpTQSfnBNxU1FtdgrJPDUbpmvtUOcO6A2FoLRRMWKLVzCtYrV+Yr23nKUB81qJIdYqBNo15pJf8mv1MeyqNzaAVYU7QoZ/nuiCjMcK3rt4KLWbc5pg3DAYd0YrPdmtukk3hhEUmGIOucuMzekWAJqWtqUlnhzsjejiEAzH9kmtUcP1kvWHKC9kcqb",
                                "ttl": 3598,
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        },
                        "errors": [
                            {
                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "query_options": [
                                    "TCP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ]
                    }
                ]
            },
            "tk37o.m2htw.fail04.dnssec.works./IN/A": {
                "nxdomain": [
                    {
                        "id": "tk37o.m2htw.fail04.dnssec.works./IN/A",
                        "proof": [
                            {
                                "id": "NSEC",
                                "description": "NSEC record(s) proving the non-existence (NXDOMAIN) of tk37o.m2htw.fail04.dnssec.works",
                                "nsec": [
                                    {
                                        "id": "fail04.dnssec.works./IN/NSEC",
                                        "description": "RRset for fail04.dnssec.works/NSEC",
                                        "name": "fail04.dnssec.works.",
                                        "ttl": 3598,
                                        "type": "NSEC",
                                        "rdata": [
                                            "why.fail04.dnssec.works. A NS SOA TXT AAAA RRSIG NSEC DNSKEY"
                                        ],
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ],
                                        "rrsig": [
                                            {
                                                "id": "fail04.dnssec.works./8/44118",
                                                "description": "RRSIG covering fail04.dnssec.works/NSEC",
                                                "signer": "fail04.dnssec.works.",
                                                "algorithm": 8,
                                                "key_tag": 44118,
                                                "original_ttl": 3600,
                                                "labels": 3,
                                                "inception": "2021-01-01 00:00:00 UTC",
                                                "expiration": "2070-01-01 00:00:00 UTC",
                                                "signature": "h7vX5B8St9vzfGLhjsNvnG48utmR2SWhkvOoopt6y73M/wbjMhfMXFNHzFJyoEdLXEg4w2uFcdbS4DCydnrxLYQ55e0BCK/tCeBv+KnkpKU+IZIPw6SPp3nYNKBFqGTXyIGxY5UqyI0aAuCqQp6jf59bzaHQJZvsEvJi5Uap+iRIoir0AEItXoeppxGiQ9L75ZIFwESl95TmI17dy5e7tnBRS8PH+q/3nggMDLgAywHqFlwJk2zrt0V2/TbLG+xZ",
                                                "ttl": 3598,
                                                "status": "VALID",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "ns_names": [
                                                    "ns0."
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ],
                                        "errors": [
                                            {
                                                "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                                "code": "MISSING_RRSIG_FOR_ALG_DS",
                                                "servers": [
                                                    "192.168.46.106"
                                                ],
                                                "query_options": [
                                                    "UDP_+C_EDNS0_4096_D_NK"
                                                ]
                                            }
                                        ]
                                    }
                                ],
                                "sname_covering": {
                                    "covered_name": "tk37o.m2htw.fail04.dnssec.works.",
                                    "nsec_owner": "fail04.dnssec.works.",
                                    "nsec_next": "why.fail04.dnssec.works."
                                },
                                "wildcard_covering": {
                                    "covered_name": "*.fail04.dnssec.works.",
                                    "nsec_owner": "fail04.dnssec.works.",
                                    "nsec_next": "why.fail04.dnssec.works."
                                },
                                "status": "VALID",
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ]
                            }
                        ],
                        "soa": [
                            {
                                "id": "fail04.dnssec.works./IN/SOA",
                                "description": "RRset for fail04.dnssec.works/SOA",
                                "name": "fail04.dnssec.works.",
                                "ttl": 3598,
                                "type": "SOA",
                                "rdata": [
                                    "ns2.myinfrastructure.org. hostmaster.strotmann.de. 17 86400 7200 3542400 3600"
                                ],
                                "servers": [
                                    "192.168.46.106"
                                ],
                                "ns_names": [
                                    "ns0."
                                ],
                                "query_options": [
                                    "UDP_+C_EDNS0_4096_D_NK"
                                ],
                                "rrsig": [
                                    {
                                        "id": "fail04.dnssec.works./8/44118",
                                        "description": "RRSIG covering fail04.dnssec.works/SOA",
                                        "signer": "fail04.dnssec.works.",
                                        "algorithm": 8,
                                        "key_tag": 44118,
                                        "original_ttl": 3600,
                                        "labels": 3,
                                        "inception": "2021-01-01 00:00:00 UTC",
                                        "expiration": "2070-01-01 00:00:00 UTC",
                                        "signature": "C+eQdjrQMIJRZRdO3nNVEpFAVWt9/58cSOOSXBQFRlj+3e2M/+1h1qds+0SPtJv+lsYAjDbEAKrSsoc3jyqMMjyW71DWm+K2EMz/m3U1l/RvWQDQ7vXuECsBcF2uXkKYpUbIPHQooRG/I9mDcBy6xJx3IBuEt6I3JCqRS9Z5z8ZgJyTHJJqkFycl2tP8c/22luHphN9yTfftL7qAEZkXJDhaqOSadgdvzFlsGZj6rVyLK1cmc9EMNrPxUnOWWjAH",
                                        "ttl": 3598,
                                        "status": "VALID",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "ns_names": [
                                            "ns0."
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ],
                                "errors": [
                                    {
                                        "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no RRSIG with algorithm 7 covering the RRset was returned in the response.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                                        "code": "MISSING_RRSIG_FOR_ALG_DS",
                                        "servers": [
                                            "192.168.46.106"
                                        ],
                                        "query_options": [
                                            "UDP_+C_EDNS0_4096_D_NK"
                                        ]
                                    }
                                ]
                            }
                        ],
                        "servers": [
                            "192.168.46.106"
                        ],
                        "ns_names": [
                            "ns0."
                        ],
                        "query_options": [
                            "UDP_+C_EDNS0_4096_D_NK"
                        ],
                        "cookie_status": {
                            "192.168.46.106": {
                                "request": "CLIENT_COOKIE_ONLY",
                                "response": "CLIENT_AND_SERVER_COOKIE"
                            }
                        }
                    }
                ]
            }
        },
        "dnskey": [
            {
                "id": "8/9127",
                "description": "DNSKEY for fail04.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 9127)",
                "flags": 257,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAeixmnzdleIbyGfP9k52kFjo0qzR2AbE8icgZrI8RV2Zc1wf4t8qQsv3HtceRLwqldsHtlMGTdrKMo+DbzbiIcfxOx7Imago4pkjmlnvAT6wi4zdEF39/hv8miISh/ddI+t1pa3OOqONA4CyUckcS6Q0qLVWBXetXIVu/TtF06VkAcc7vr2Ml4Gt5XAK4TMBVdrtNQxc/ARY+X9Ms2GvBATs77NvfuXFNFifZA20P0lJw/CFW/t+8ImHGtwEhKfThueNozeJ/eMn0mGjvrtyGJ2ww2DBsGL+fAPr+ODAntoJjo/ftZREJOsvZ7VvG9QTvD0XXeNwMXc18P59QtZVkyJ062SrcRxg5KpAf3sbkwE0snVOqGuXbEjX+6CsVSrB8BqhFV4RxCxSVwziZSaoUHne4d9oNuOeh00aD9TOKRgb",
                "ttl": 3598,
                "key_length": 2560,
                "key_tag": 9127,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+C_EDNS0_4096_D_NK"
                ]
            },
            {
                "id": "8/44118",
                "description": "DNSKEY for fail04.dnssec.works (algorithm 8 (RSA/SHA-256), key tag 44118)",
                "flags": 256,
                "protocol": 3,
                "algorithm": 8,
                "key": "AwEAAcgPNRU1zeVIZG9Kwa0SsMSDnMa8H18qxU0ZW1QEFveujkRdWO6L7/iokazZWVMeKmv4pGGyMOKTmgDl96yzEjgbtjCoHrd4mql6EFoQulbWkz/AXDgj0TeeX1863jGHJuEDiQQhnKPSBNx1vJ7tJfexAZV0UMU/lglmySKn4Nr9mVmg73dzWPBbvE+NkrBaH9+7/S+RNjBEq4r73LBwBVLZgnVlnL3Ti4xyVfizq319RagEoFjuUeLGSoI4Vk5nFw==",
                "ttl": 3598,
                "key_length": 1536,
                "key_tag": 44118,
                "servers": [
                    "192.168.46.106"
                ],
                "ns_names": [
                    "ns0."
                ],
                "query_options": [
                    "TCP_+C_EDNS0_4096_D_NK"
                ]
            }
        ],
        "delegation": {
            "ds": [
                {
                    "id": "7/6502/2",
                    "description": "DS record(s) corresponding to DNSKEY for fail04.dnssec.works (algorithm 7 (RSASHA1-NSEC3-SHA1), key tag 6502)",
                    "algorithm": 7,
                    "key_tag": 6502,
                    "digest_type": 2,
                    "digest": "pYc5SgviR2J+O8XKWphbp/ZhFFVEZHHOoe6RGX3SaME=",
                    "ttl": 57,
                    "status": "INDETERMINATE_NO_DNSKEY",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "ns_names": [
                        "ns0."
                    ],
                    "query_options": [
                        "UDP_+_EDNS0_4096_D_NK"
                    ]
                }
            ],
            "status": "BOGUS",
            "errors": [
                {
                    "description": "No valid RRSIGs made by a key corresponding to a DS RR were found covering the DNSKEY RRset, resulting in no secure entry point (SEP) into the zone.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                    "code": "NO_SEP",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "query_options": [
                        "TCP_+C_EDNS0_4096_D_NK"
                    ]
                },
                {
                    "description": "The DS RRset for the zone included algorithm 7 (RSASHA1NSEC3SHA1), but no DS RR matched a DNSKEY with algorithm 7 that signs the zone's DNSKEY RRset.  See RFC 4035, Sec. 2.2, RFC 6840, Sec. 5.11.",
                    "code": "MISSING_SEP_FOR_ALG",
                    "servers": [
                        "192.168.46.106"
                    ],
                    "query_options": [
                        "TCP_+C_EDNS0_4096_D_NK"
                    ]
                }
            ]
        }
    }
}
'''

#DNSVIZ_RESULT = DNSVIZ_RESULT_FAIL04_DNSSEC_WORKS
DNSVIZ_RESULT = DNSVIZ_RESULT_APPLE_COM
#DNSVIZ_RESULT = DNSVIZ_RESULT_HINDENBURGRING_COM

ZONE_STATUS_OK = ("NOERROR",)
RRSIG_STATUS_OK = ("VALID",)
DS_STATUS_OK = ("VALID",)
DELEGATION_STATUS_OK = ("SECURE", )
DELEGATION_STATUS_WARN = ("INSECURE", )

class DNSviz():
    def __init__(self, plugin, zone, debug=False):
        self._plugin = plugin
        self._zone = zone
        self._debug = debug

    @property
    def plugin(self):
        return self._plugin

    @property
    def zone(self):
        return self._zone

    @property
    def debug(self):
        return self._debug

    def _check_rrsig(self, rrsig, query, proof=None):
        status = rrsig.get("status")
        key_tag = rrsig.get("key_tag")
        inception = datetime.strptime(rrsig.get("inception"), "%Y-%m-%d %H:%M:%S %Z")
        expiration = datetime.strptime(rrsig.get("expiration"), "%Y-%m-%d %H:%M:%S %Z")

        if status not in RRSIG_STATUS_OK:
            self.plugin.add_summary(f'RRSIG status of query "{query}" is {status} (RRSIG key {key_tag})')
            self.plugin.add_status(critical)

    def _check_nodata_proof(self, rrsig):
        pass

    def check_dnssec(self):
        if self.debug:
            print(f'Checking DNSSEC status for zone "{self.zone}"')

        result = json.loads(DNSVIZ_RESULT)

        for zone_name, zone_result in result.items():
            self.check_zone_result(zone_name, zone_result)

    def check_query_result(self, query, query_result):
        if self.debug:
            print(f'Checking results for query "{query}"')

        if answer := query_result.get("answer"):
            if rrsigs := answer[0].get("rrsig"):
                for rrsig in rrsigs:
                    self._check_rrsig(rrsig, query)
            else:
                self.plugin.add_summary(f'Answer for query "{query}" is unsigned')
                self.plugin.add_status(warning)

        elif nodata := query_result.get("nodata"):
            if proofs := nodata[0].get("proof"):
                for proof in proofs:
                    self._check_nodata_proof(proof)
            else:
                self.plugin.add_summary(f'NODATA answer for query "{query}" does not provide proof of non-existence')
                self.plugin.add_status(warning)

        elif nxdomain := query_result.get("nxdomain"):
            if proofs := nxdomain[0].get("proof"):
                for proof in proofs:
                    self._check_nodata_proof(proof)
            else:
                self.plugin.add_summary(f'NXDOMAIN answer for query "{query}" does not provide proof of non-existence')
                self.plugin.add_status(warning)

        else:
            self.plugin.add_summary(f'Neither answer nor NODATA nor NXDOMAIN received for query "{query}"')
            self.plugin.add_status(unknown)

    def check_delegation(self, zone_name, delegation_result):
        if self.debug:
            print(f'Checking delegation for zone "{zone_name}"')

        status = delegation_result.get("status")
        if status not in DELEGATION_STATUS_OK:
            if status in DELEGATION_STATUS_WARN:
                self.plugin.add_status(warning)
            else:
                self.plugin.add_status(critical)
            self.plugin.add_summary(f'Delegation status for zone "{zone_name}" is {status}')

        if ds_records := delegation_result.get("ds"):
            for ds in ds_records:
                if (ds_status := ds.get("status")) not in DS_STATUS_OK:
                    self.plugin.add_status(warning)
                    self.plugin.add_summary(f'DS status for zone "{zone_name}" is {ds_status}')

            if errors := delegation_result.get("errors"):
                for error in errors:
                    self.plugin.add_summary(error.get("description"))

        return status in DELEGATION_STATUS_OK

    def check_zone_result(self, zone_name, zone_result):
        if self.debug:
            print(f'Checking results for zone "{zone_name}"')

        zone_level = 0 if zone_name == "." else len(zone_name.split("."))-1

        if (status := zone_result.get("status")) not in ZONE_STATUS_OK:
            self.plugin.add_summary(f'Status of zone "{zone_name}" is {status}')
            self.plugin.add_status(critical)

        check_queries = True

        if zone_name != ".":
            check_queries = self.check_delegation(zone_name, zone_result.get("delegation"))

        if check_queries:
            for query, query_result in zone_result.get("queries", {}).items():
                self.check_query_result(query, query_result)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", "-d", action="store_true", help="Provide debug output")
    parser.add_argument("--zone", "-z", type=str, required=True, help="Zone to check the DNSSEC validity for")

    args = parser.parse_args()

    plugin=PluginHelper()

    dnsviz = DNSviz(
        plugin=plugin,
        zone=args.zone,
        debug=args.debug,
    )

    plugin.add_status(ok)

    dnsviz.check_dnssec()

    if plugin.get_status() == ok:
        plugin.add_summary("DNSSEC status is OK")

    plugin.exit()


if __name__ == "__main__":
    main()
