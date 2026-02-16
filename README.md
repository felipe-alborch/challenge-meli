## MELI DataSec Challenge
Arquitectura Multiagente para Priorización Inteligente de Detectores

Este proyecto implementa una arquitectura multiagente secuencial para diseñar, enriquecer y priorizar detectores de seguridad alineados a tendencias reales del Verizon Data Breach Investigations Report (DBIR) 2025 y al framework MITRE ATT&CK.

---

El sistema combina:

Análisis contextual estratégico (DBIR)

Enriquecimiento dinámico vía MCP (MITRE)

Modelo de scoring cuantitativo de riesgo

Generación automática de reporte priorizado

---

## Arquitectura del Sistema

El pipeline está compuesto por 3 agentes especializados, ejecutados en forma estrictamente secuencial: Analyzer → Classifier → Reporter

Cada agente transforma el output del anterior.

---

## Analyzer (Agente 1):

Responsable de:

- Analizar el contexto del ecosistema (inputs/template_input.txt)
- Utilizar un subconjunto del DBIR 2025 (data/dbir_2025_subset.txt) 
- Proponer hasta 5 detectores estratégicos
- Cada detector incluye:
  - Objetivo
  - Datos necesarios
  - Lógica de detección
  - Posibles falsos positivos
  - Ideas de tuning
  - Justificación alineada a DBIR
  - Categoría sugerida (category_hint)
  - Flags de telemetría (telemetry_flags)

El Analyzer no asigna riesgo ni MITRE.

---

## Classifier (Agente 2):

Responsable de:

- Mapear detectores a técnicas MITRE ATT&CK
- Calcular criticidad mediante modelo cuantitativo
- Ordenar por prioridad

## Integración con MITRE vía MCP

El sistema utiliza el servidor mitre-mcp (existente) en modo HTTP.
Para cada técnica:

- Se consulta dinámicamente la tool get_technique_by_id
- Se parsea la respuesta MCP
- Se enriquece el detector con:
  - technique
  - name
  - metadata oficial

No se utiliza mapeo hardcodeado de nombres.

## Modelo de Riesgo

El scoring se calcula mediante: risk_score = impact * likelihood * 10
Y se clasifica en:

Risk Score -	Nivel
< 100	     -  Low
100–199	   -  Medium
≥ 200	     -  High

Los detectores se ordenan en forma descendente por criticidad.

---

## Reporter (Agente 3):

Genera: runs/<session_id>/report.md

Incluye:
- Detectores priorizados
- Nivel y score de riesgo
- Justificación técnica
- Mapeo MITRE ATT&CK
- Descripción completa del detector

---

## Uso del DBIR 2025

El archivo dbir_2025_subset.txt se utiliza como referencia estratégica.

Objetivo:
- Alinear propuestas con tendencias reales
- Priorizar amenazas prevalentes
- Justificar diseño de detectores

No se realiza parsing estructural completo del DBIR.

---

## Integración MCP (MITRE ATT&CK)

El sistema depende de un servidor MCP externo: mitre-mcp

Se utiliza el transporte Streamable HTTP.

Si el MCP no está disponible:
- El pipeline no se detiene
- El nombre MITRE se marca como Unknown
- El scoring y reporte siguen funcionando
- Esto garantiza resiliencia del pipeline.

---

## Requisitos:

- Python 3.10+
- Dependencias definidas en requirements.txt

Instalación: python -m pip install -r requirements.txt

---

## Ejecución

Paso 1 — Levantar MITRE MCP (Terminal 1): mitre-mcp --http --host localhost --port 8000
       — O en Windows: C:\Users\<user>\AppData\Local\Programs\Python\Python312\Scripts\mitre-mcp.exe --http --host localhost --port 8000

Esta terminal debe permanecer abierta.

Paso 2 — Ejecutar el pipeline (Terminal 2): python -m app.main
       — O con input personalizado: python -m app.main --input inputs/template_input.txt

---

## Outputs Generados

Cada ejecución crea: runs/<session_id>/

Contiene:
- analyzer.json
- classifier.json
- reporter.json
- report.md

---

## Decisiones de Diseño

- Arquitectura modular y desacoplada
- Pipeline resiliente ante fallas externas (MCP)
- Enriquecimiento dinámico en lugar de hardcoding
- Persistencia de cada etapa para trazabilidad
- Modelo de riesgo cuantitativo reproducible

## Objetivo del Proyecto

Demostrar:
- Diseño de arquitectura multiagente
- Priorización basada en riesgo cuantitativo
- Integración con estándares de la industria (MITRE ATT&CK)
- Uso de MCP existentes
- Generación automática de reporte técnico accionable

## Notas Finales

- El sistema está diseñado para:
- Ser extensible (nuevos agentes)
- Adaptarse a otros MCP
- Incorporar nuevos modelos de scoring
- Integrarse a flujos de Security Engineering

## Estado del Proyecto

- Arquitectura funcional
- Integración MCP real
- Enriquecimiento dinámico MITRE
- Priorización cuantitativa
- Generación de reporte automático