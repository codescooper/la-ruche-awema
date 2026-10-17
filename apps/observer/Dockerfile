FROM python:3.12-alpine
WORKDIR /app
COPY server.py engine.py catalog.py activity_schema.py classroom_view.py replay_schema.py trace_schema.py financial_qualification.json /app/
COPY public /app/public
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
EXPOSE 8080
CMD ["python", "/app/server.py"]
