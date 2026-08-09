FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev tor \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
# en_core_web_sm is installed directly via requirements.txt (see config/settings.yaml
# nlp.spacy_model). The much larger en_core_web_trf is opt-in — uncomment the line below if
# you want the higher-accuracy transformer model baked into the image (~500MB, slow build).
RUN pip install --no-cache-dir -r requirements.txt
# RUN python -m spacy download en_core_web_trf

COPY . .

ENV PYTHONUNBUFFERED=1
