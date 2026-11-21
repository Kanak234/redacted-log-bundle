```mermaid
flowchart LR
 A[UTF-8 snapshot] --> B[Presidio and India rules]
 A --> C[Gitleaks JSON]
 B --> D[Union overlapping spans]
 C --> D
 D --> E[HMAC replacement]
 E --> F[Text, preview and counts]
```
