### Как запустить локально
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m uvicorn main:app --reload --port 3000
```

Swagger будет доступен по http://127.0.0.1:3000/docs
