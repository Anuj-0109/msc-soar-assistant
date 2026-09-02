# Intent-Based SOAR Prototype Using Rasa NLP for Intelligent Incident Response

## Overview

This project presents an MSc Computer Science dissertation prototype for an
intent-based Security Orchestration, Automation and Response (SOAR) platform.

The system combines natural-language intent recognition using Rasa NLP with
security incident handling, threat-intelligence enrichment, log ingestion,
playbook execution, incident management, geolocation, analytics, audit
logging and reporting.

The prototype investigates how intent-based natural-language interaction can
support security analysts during incident-response workflows.

## Main Objectives

The system aims to:

- interpret security-related user requests through Rasa NLP;
- classify requests into predefined security intents;
- support security incident creation and management;
- ingest and analyse security logs;
- analyse indicators of compromise (IOCs);
- obtain threat-intelligence information from external services;
- support simulated containment and firewall operations;
- execute security-response playbooks;
- provide IP geolocation information;
- maintain audit information for security operations;
- provide operational dashboards and supervisor demonstration functionality;
- generate incident and executive reports;
- evaluate the Rasa intent-classification component using quantitative
  evaluation artefacts.

## System Architecture

The prototype is implemented as a modular Python application.

### Application Layer

The main Flask application is implemented in `app.py`.

The application registers separate Flask blueprints for:

- incident management;
- playbooks;
- log ingestion;
- natural-language chat;
- analytics;
- supervisor demonstration;
- intelligence and reporting.

### NLP Layer

Rasa 3.6.21 is used for natural-language understanding.

The Rasa project consists of:

- `domain.yml` — intents, entities, slots and responses;
- `data/nlu.yml` — NLU training examples;
- `data/rules.yml` — conversation rules;
- `data/stories.yml` — conversation stories;
- `actions/actions.py` — custom Rasa actions;
- `config.yml` — Rasa model configuration;
- `endpoints.yml` — endpoint configuration.

### SOAR and Incident Response Layer

The project contains components for:

- incident creation, retrieval, updating and deletion;
- incident comments;
- IOC analysis;
- security-log ingestion;
- playbook execution;
- firewall-rule operations;
- simulated containment and unblocking workflows;
- audit logging;
- intelligence and executive reporting.

### Threat Intelligence

Threat-intelligence functionality is implemented in:

`services/threat_intel.py`

The application supports configuration for external threat-intelligence
providers through environment variables. Real API credentials are not
included in this repository.

### Geolocation

IP geolocation functionality is implemented in:

`services/geolocation.py`

Runtime geolocation caches and databases are excluded from version control.

### Web Interface

The Flask application provides an operational web interface using HTML, CSS
and JavaScript.

The interface includes functionality associated with:

- operations workspace;
- playbook management;
- supervisor demonstration;
- incident workflows;
- analytics;
- intelligence and reporting.

## Project Structure

```text
msc-soar-assistant/
├── actions/
│   ├── actions.py
│   └── __init__.py
├── blueprints/
│   ├── analytics.py
│   ├── chat.py
│   ├── incidents.py
│   ├── ingestion.py
│   ├── intelligence_reporting.py
│   ├── playbooks.py
│   └── supervisor_demo.py
├── data/
│   ├── nlu.yml
│   ├── rules.yml
│   └── stories.yml
├── dissertation_appendix_evidence/
├── evaluations/
├── models/
│   └── database.py
├── services/
│   ├── geolocation.py
│   ├── log_analysis.py
│   ├── playbook_engine.py
│   └── threat_intel.py
├── static/
├── templates/
├── tests/
├── app.py
├── audit_logger.py
├── config.yml
├── constants.py
├── credentials.yml
├── domain.yml
├── endpoints.yml
├── evaluate.sh
├── requirements.txt
├── settings.py
├── soar_engine.py
└── .env.example
