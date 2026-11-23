"""Popular package names, for catching look-alike (typosquat) dependencies."""

NPM = """
react react-dom vue angular svelte next nuxt express koa fastify axios lodash underscore moment dayjs
chalk commander yargs debug request node-fetch cross-env dotenv uuid classnames prop-types redux
react-redux zustand mobx rxjs typescript webpack vite rollup esbuild babel-core @babel/core eslint
prettier jest mocha chai sinon cypress playwright puppeteer socket.io ws mongoose sequelize prisma
pg mysql mysql2 sqlite3 redis ioredis jsonwebtoken bcrypt bcryptjs passport cors helmet morgan
body-parser cookie-parser multer nodemon pm2 concurrently rimraf glob minimist semver tslib colors
async bluebird inquirer ora boxen figlet electron tailwindcss postcss autoprefixer sass less
styled-components emotion @mui/material antd bootstrap jquery three d3 chart.js firebase
@supabase/supabase-js aws-sdk openai @anthropic-ai/sdk discord.js telegraf crypto-js ethers web3
solc hardhat truffle bignumber.js dotenv-expand node-sass sharp jimp canvas pdfkit xlsx papaparse
preact cheerio jsdom marked markdown-it highlight.js zod joi yup ajv graphql apollo-server @apollo/client
""".split()

PYPI = """
requests numpy pandas scipy matplotlib seaborn scikit-learn sklearn tensorflow keras torch torchvision
transformers datasets tokenizers accelerate flask django fastapi uvicorn gunicorn starlette pydantic
sqlalchemy psycopg2 psycopg2-binary pymysql redis celery boto3 botocore urllib3 certifi idna chardet
charset-normalizer setuptools wheel pip six python-dateutil pytz pyyaml jinja2 markupsafe click
colorama tqdm rich typer pillow opencv-python beautifulsoup4 bs4 lxml selenium scrapy httpx aiohttp
websockets pytest tox black flake8 mypy pylint isort openai anthropic langchain cryptography pycryptodome
paramiko fabric docker kubernetes pyjwt bcrypt passlib python-dotenv discord.py python-telegram-bot
pyautogui pynput keyboard pyinstaller nuitka web3 eth-account solana jupyter notebook ipython
matplotlib-inline plotly dash streamlit gradio onnxruntime onnx xgboost lightgbm catboost nltk spacy
""".split()


_POPULAR_CACHE: dict = {}


def is_popular(name: str, ecosystem: str, threshold: int = 2_000) -> bool:
    """Ask the public registry how often the package is downloaded. A real
    package that merely looks like another (preact/react) has many weekly
    downloads (eclint ~10k a week); a typosquat has few. Offline, it counts as not popular. Only
    the package name is sent."""
    import json
    import urllib.parse
    import urllib.request
    key = (ecosystem, name.lower())
    if key in _POPULAR_CACHE:
        return _POPULAR_CACHE[key]
    q = urllib.parse.quote(name, safe="@")
    url = (f"https://api.npmjs.org/downloads/point/last-week/{q}" if ecosystem == "npm"
           else f"https://pypistats.org/api/packages/{q.lower()}/recent")
    result = False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "guardpost"})
        with urllib.request.urlopen(req, timeout=4) as r:
            data = json.load(r)
        n = data.get("downloads") if ecosystem == "npm" else (data.get("data") or {}).get("last_week")
        result = isinstance(n, int) and n >= threshold
    except Exception:
        result = False
    _POPULAR_CACHE[key] = result
    return result


import datetime as _dt

YEARS_AGO_2 = (_dt.date.today() - _dt.timedelta(days=730)).isoformat()


def first_published(name: str, ecosystem: str) -> str | None:
    """ISO date the package first appeared (typosquats are usually new), or None."""
    import json
    import urllib.parse
    import urllib.request
    q = urllib.parse.quote(name, safe="@")
    url = f"https://registry.npmjs.org/{q}" if ecosystem == "npm" else f"https://pypi.org/pypi/{q}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "guardpost", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=6) as r:
            data = json.load(r)
        if ecosystem == "npm":
            return (data.get("time") or {}).get("created")
        times = [f["upload_time_iso_8601"] for files in (data.get("releases") or {}).values() for f in files
                 if f.get("upload_time_iso_8601")]
        return min(times) if times else None
    except Exception:
        return None


def edit1(a: str, b: str) -> bool:
    """True if a and b differ by exactly one edit (or a swap of neighbours)."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        diff = [i for i in range(len(a)) if a[i] != b[i]]
        if len(diff) == 1:
            return True
        return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]
    if len(a) > len(b):
        a, b = b, a
    for i in range(len(b)):
        if a == b[:i] + b[i + 1:]:
            return True
    return False


def lookalike(name: str, ecosystem: str) -> str | None:
    known = NPM if ecosystem == "npm" else PYPI
    n = name.lower().replace("_", "-")
    if n in known or len(n) < 4:
        return None
    for k in known:
        if len(k) >= 4 and edit1(n, k):
            return k
    # separators played with: "python-requests" "requests-py" "reqeusts"
    for k in known:
        if len(k) >= 5 and n.replace("-", "") == k.replace("-", "") and n != k:
            return k
    return None
