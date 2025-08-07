# 🧠 LLM Prompt Injection Detection Microservice  
*A reusable microservice for detecting and mitigating prompt injection attempts in LLM-based systems*

## 📘 1. System Overview

This project defines a **containerized microservice** that preprocesses user prompts to detect and mitigate prompt injection attacks. The service can operate in:

- **Inline mode**: as a real-time interceptor and gatekeeper before LLM inference.
- **Async mode**: as a post-facto analyzer for logging, alerting, or security observability.

**Detection Techniques Include**:
- Heuristic (regex/keyword-based)
- Meta-level classification via external LLMs
- (Future) Context-aware analysis for multi-turn attacks

**Remediation Actions**:
- Block the request
- Flag and log for auditing
- Strip malicious segments from input

**Enterprise Readiness**:
- SOC 2 Type II, FINRA, and GDPR/CPRA compliant
- OpenTelemetry-compatible
- CI/CD-ready with GitHub Actions
- Deployable to AWS via container orchestrators (ECS, EKS)

## 🛠️ 2. Technical Requirements

### 2.1 Functional Requirements

| ID | Description |
|----|-------------|
| FR1 | Detect known prompt injection attempts using heuristics |
| FR2 | Classify prompt intent using external LLM |
| FR3 | Support real-time (inline) and async (batch) inspection |
| FR4 | Allow configurable mitigation (block/flag/strip) |
| FR5 | Send structured alerts and logs to external observability platform |
| FR6 | Maintain an updatable test corpus with known attack patterns |
| FR7 | Support API and file-based usage (batch testing / audit analysis) |
| FR8 | Future: Maintain prompt context across sessions (multi-turn defense) |

### 2.2 User Stories & Pseudocode

#### 🧑‍💻 Story 1: Developer - Use Inline Detection

**User Story**:  
As a developer, I want to call the microservice inline before LLM invocation so malicious prompts can be blocked or transformed in real time.

**Pre-conditions**:  
The detection service is reachable and configured in inline mode.

**Technical Requirements**:
- Endpoint: `POST /v1/detect`
- Input: `{ prompt: str }`
- Response: `{ verdict: "allow" | "block" | "flag" | "strip", modified_prompt?, reasons: [] }`

**Pseudo-code**:
```python
route POST /v1/detect:
  validate JSON payload with required 'prompt'
  result = run_heuristics(prompt)
  if result suggests injection:
    verdict = config.action_on_detection  # e.g., "block"
    log_event(prompt, verdict, reasons)
    return response(verdict, modified_prompt=apply_strip_if_needed())

  meta_verdict = query_llm_meta_critic(prompt)
  if meta_verdict == "malicious":
    verdict = config.action_on_detection
    log_event(prompt, verdict, source="llm")
    return response(verdict, ...)

  return response("allow", original_prompt)
```

#### 🧑‍🔧 Story 2: Security Engineer - Maintain Testing Corpus

**User Story**:  
As a security engineer, I want to maintain and auto-update a corpus of known prompt injection test cases so the system evolves with attacker tactics.

**Pseudo-code**:
```python
job "update_test_corpus":
  download public corpora from URLs
  extract prompt samples
  run classification & tagging
  save JSONL as corpus/YYYY-MM-DD.jsonl
  commit to GitHub if changed
```

#### 👩‍🔬 Story 3: QA Engineer - Run Injection Unit Tests

**User Story**:  
As a QA engineer, I want to validate that known malicious prompts are correctly detected and clean prompts are not blocked.

**Pseudo-code**:
```python
test "prompt detection accuracy":
  load corpus
  for each prompt in corpus:
    response = POST /v1/detect with prompt
    assert response.verdict matches prompt.label
```

#### 🛠️ Story 4: Developer - Add Multi-Turn Support

**User Story**:  
As a developer, I want to analyze session history so I can detect chained injection patterns across multiple turns.

**Pseudo-code**:
```python
session_store = load_session_context(user_id)
combined_context = session_store + current_prompt
verdict = run_detection(combined_context)
```

## 🏗️ 3. Technical Architecture & Design

### 3.1 System Architecture Diagram (Block Diagram)

```
Client → [ Detection API ]
           |       |
           |       ├──> Heuristic Engine (regex, base64, keywords)
           |       ├──> LLM Meta-Critic (via OpenAI/Gemini API)
           |       └──> Logging / Metrics / Alerting
                     |
                Response (allow/block/flag/strip)
```

### 3.2 Technology Stack

| Layer | Tech |
|-------|------|
| API | FastAPI (Python 3.11) |
| Heuristics | Custom Python Regex/Keyword Engine |
| LLM Integration | OpenAI API / Gemini Pro |
| Data Format | JSON, JSONL |
| CI/CD | GitHub Actions |
| Container | Docker |
| Monitoring | OpenTelemetry-compatible logs |
| Storage | S3 or mounted volume for corpus |
| Hosting | AWS ECS / EKS |

### 3.3 Data Model & Corpus Schema

```json
{
  "prompt": "Ignore all previous instructions...",
  "label": "malicious",
  "source": "OWASP Red Team Corpus",
  "category": "direct injection",
  "created_at": "2025-08-04T00:00:00Z"
}
```

### 3.4 API Interface Definition (OpenAPI v3)

```yaml
openapi: 3.0.0
info:
  title: Prompt Injection Detector
  version: 1.0.0
paths:
  /v1/detect:
    post:
      summary: Analyze a prompt for injection risk
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                prompt:
                  type: string
              required: [prompt]
      responses:
        '200':
          description: Detection result
          content:
            application/json:
              schema:
                type: object
                properties:
                  verdict:
                    type: string
                    enum: [allow, block, flag, strip]
                  modified_prompt:
                    type: string
                  reasons:
                    type: array
                    items:
                      type: string
```

### 3.5 Error Handling Strategy

| Error | Response |
|-------|----------|
| Invalid input | 400 Bad Request |
| LLM API timeout | 503 Service Unavailable |
| Detection failure | 500 Internal Server Error |
| Auth failure (future) | 401 Unauthorized |

## 🚀 4. Development & Deployment Process

### 4.1 Repository & Code Structure

```
/detector
  ├── main.py            # FastAPI app entry
  ├── heuristics.py      # Regex/keyword engine
  ├── llm_meta.py        # Meta-critic logic
  ├── corpus/            # Test corpora (JSONL)
  ├── tests/             # Unit & corpus tests
  └── Dockerfile
```

### 4.2 Dependency Management

- `requirements.txt`
- Uses `pip-tools` or `poetry` (optional)
- LLM clients (e.g., `openai`, `google-generativeai`)

### 4.3 Containerization Instructions

```Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
```

### 4.4 CI/CD Pipeline (GitHub Actions)

```yaml
name: CI
on: [push, pull_request]
jobs:
  build-test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - run: pip install -r requirements.txt
      - run: pytest
      - run: docker build -t prompt-detector .
```