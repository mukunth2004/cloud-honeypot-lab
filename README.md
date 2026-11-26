# Cloud honeypot with automated response

An SSH honeypot on AWS that logs attackers, detects bad behaviour in Elastic, and blocks the source address automatically.

## Architecture

```mermaid
flowchart LR
    ATT([Internet visitors])

    subgraph AWS["AWS (eu-north-1), built with Terraform"]
        NACL["Network ACL<br/>stateless, deny rules"]
        subgraph EC2["EC2 instance"]
            COW["Cowrie honeypot<br/>(Docker)"]
            FB["Filebeat"]
        end
        LAM["Lambda<br/>block-ip"]
        DDB[("DynamoDB<br/>block records")]
        EB["EventBridge<br/>every 5 min"]
    end

    ELK["Elastic Security<br/>(serverless)<br/>2 detection rules"]

    ATT -->|SSH| NACL --> COW
    COW -->|JSON logs| FB
    FB -->|HTTPS| ELK
    ELK -->|webhook + secret| LAM
    LAM -->|add deny rule| NACL
    LAM <-->|rule numbers, 2 h expiry| DDB
    EB -->|cleanup| LAM
```
