from flask import Flask, request, redirect, url_for, session, flash, render_template_string, abort
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
import sqlite3, os, secrets

app = Flask(__name__)
app.secret_key = os.environ.get("SIKANDER_SECRET_KEY", "sikander-local-dev-key-change-before-hosting")
DB_NAME = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sikander_f1_store.db")

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def connect():
    db = sqlite3.connect(DB_NAME)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    return db

def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL, role TEXT NOT NULL,
            full_name TEXT DEFAULT '', phone TEXT DEFAULT '', address TEXT DEFAULT '',
            created_at TEXT DEFAULT '')""")
        db.execute("""CREATE TABLE IF NOT EXISTS medicines(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT DEFAULT '',
            purchase_price REAL DEFAULT 0, sale_price REAL DEFAULT 0, stock INTEGER DEFAULT 0,
            details TEXT DEFAULT '', added_by INTEGER, updated_at TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS settings(
            id INTEGER PRIMARY KEY CHECK(id=1), shop_name TEXT, phone TEXT, address TEXT, owner TEXT)""")
        db.execute("""CREATE TABLE IF NOT EXISTS orders(
            id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INTEGER,
            customer_name TEXT NOT NULL, phone TEXT NOT NULL, address TEXT DEFAULT '',
            notes TEXT DEFAULT '', status TEXT DEFAULT 'Pending', total REAL DEFAULT 0,
            payment_status TEXT DEFAULT 'Unpaid', created_at TEXT NOT NULL, FOREIGN KEY(customer_id) REFERENCES users(id))""")
        db.execute("""CREATE TABLE IF NOT EXISTS order_items(
            id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL,
            medicine_id INTEGER, medicine_name TEXT NOT NULL, quantity INTEGER NOT NULL,
            unit_price REAL NOT NULL, line_total REAL NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id) ON DELETE CASCADE)""")
        db.execute("""CREATE TABLE IF NOT EXISTS invoices(
            id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER UNIQUE NOT NULL,
            invoice_number TEXT UNIQUE NOT NULL, issued_at TEXT NOT NULL,
            FOREIGN KEY(order_id) REFERENCES orders(id))""")
        db.execute("INSERT OR IGNORE INTO settings VALUES(1,?,?,?,?)",
                   ("Sikander Medical Store", "03082443560", "Mirdad Mafi, Sahiwal", "Saad"))
        # Upgrade old users table without deleting existing accounts.
        cols = {r["name"] for r in db.execute("PRAGMA table_info(users)")}
        for col in ("full_name", "phone", "address", "created_at"):
            if col not in cols:
                db.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT ''")
        order_cols = {r["name"] for r in db.execute("PRAGMA table_info(orders)")}
        if "payment_status" not in order_cols:
            db.execute("ALTER TABLE orders ADD COLUMN payment_status TEXT DEFAULT 'Unpaid'")
        if db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            db.execute("INSERT INTO users(username,password_hash,role,full_name,created_at) VALUES(?,?,?,?,?)",
                       ("admin", generate_password_hash("Admin@123"), "admin", "Store Admin", now()))
            db.execute("INSERT INTO users(username,password_hash,role,full_name,created_at) VALUES(?,?,?,?,?)",
                       ("distributor", generate_password_hash("Dist@123"), "distributor", "Distributor", now()))

def money(v):
    return f"Rs. {float(v or 0):,.2f}"

def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(24)
    return session["_csrf"]

def check_csrf():
    if not secrets.compare_digest(request.form.get("_csrf", ""), session.get("_csrf", "")):
        abort(400)

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        return fn(*a, **kw)
    return wrapped

def roles_required(*roles):
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapped(*a, **kw):
            if session.get("role") not in roles:
                abort(403)
            return fn(*a, **kw)
        return wrapped
    return deco

BASE = r"""
<!doctype html><html lang="{{ current_lang }}" dir="{{ 'rtl' if current_lang=='ur' else 'ltr' }}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ title }} | {{ shop.shop_name }}</title><style>
:root{--navy:#10283f;--blue:#176b87;--teal:#19a6a1;--bg:#f3f7fa;--ink:#203345;--muted:#71808d;--line:#e2eaf0}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,rgba(239,248,250,.94),rgba(246,250,255,.94)),url('https://images.unsplash.com/photo-1576091160399-112ba8d25d1d?auto=format&fit=crop&w=2200&q=90') center/cover fixed;color:var(--ink);font-family:Arial,sans-serif}
a{text-decoration:none;color:inherit}.top{background:var(--navy);color:#e8f4f7;padding:9px 5%;font-size:13px;display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap}
nav{background:white;padding:15px 5%;display:flex;justify-content:space-between;align-items:center;gap:16px;box-shadow:0 4px 20px #10283f0b;position:sticky;top:0;z-index:3}
.brand{font-weight:800;font-size:19px;color:var(--navy);display:flex;align-items:center;gap:10px}.logo{width:40px;height:40px;border-radius:13px;background:linear-gradient(135deg,var(--teal),var(--blue));display:grid;place-items:center;color:white;font-size:24px}
.links{display:flex;align-items:center;gap:14px;flex-wrap:wrap;color:#526575;font-size:14px}main{max-width:1160px;margin:30px auto;padding:0 20px;min-height:58vh}
.btn{border:0;border-radius:10px;padding:11px 15px;background:var(--blue);color:white;font-weight:bold;cursor:pointer;display:inline-block;font-size:14px}.btn.light{background:#e8f4f5;color:var(--blue)}.btn.danger{background:#b83b4a}
.hero{border-radius:24px;padding:48px 6%;color:white;background:linear-gradient(100deg,rgba(8,34,55,.94),rgba(13,91,113,.72)),url('https://images.unsplash.com/photo-1585435557343-3b092031a831?auto=format&fit=crop&w=2200&q=90') center/cover;display:grid;grid-template-columns:1.4fr .6fr;align-items:center;gap:25px;min-height:300px;box-shadow:0 18px 45px #10283f25}
.hero h1{font-size:clamp(30px,5vw,48px);margin:8px 0 14px}.hero p{line-height:1.8;color:#e2f3f5}.hero-icon{font-size:110px;text-align:center}
.heading{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:30px 0 16px}.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}
.card,.panel{background:rgba(255,255,255,.94);backdrop-filter:blur(10px);border:1px solid rgba(255,255,255,.8);border-radius:17px;padding:20px;box-shadow:0 10px 30px #10283f12}.symbol{width:45px;height:45px;border-radius:13px;background:#eaf5f5;display:grid;place-items:center;font-size:23px}
.muted{color:var(--muted);font-size:14px;line-height:1.65}input,select,textarea{width:100%;padding:12px;border:1px solid #dce5ea;border-radius:9px;background:#fbfdfe;font:inherit;color:var(--ink)}textarea{min-height:85px}.field{margin-bottom:14px}label{display:block;font-size:13px;font-weight:bold;margin-bottom:6px}
.formgrid{display:grid;grid-template-columns:1fr 1fr;gap:12px}.wide{grid-column:1/-1}table{width:100%;border-collapse:collapse;background:white}th,td{text-align:start;padding:12px;border-bottom:1px solid var(--line);font-size:14px;vertical-align:top}th{background:#edf5f7}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:14px}
.pill{display:inline-block;border-radius:30px;padding:5px 9px;font-size:12px;background:#e5f6ee;color:#167447}.pill.off{background:#fff0e9;color:#a34d22}
.alert{padding:12px 15px;border-radius:10px;margin:12px 0;background:#fff3d6;color:#78540a}.alert.error{background:#ffe9eb;color:#9b2635}.stats{font-size:30px;font-weight:800;color:var(--blue);margin-top:8px}.actions{display:flex;gap:7px;flex-wrap:wrap}
footer{margin-top:45px;background:var(--navy);color:#d8e6ed;text-align:center;padding:27px 5%;font-size:13px;line-height:1.8}
@media(max-width:760px){nav{align-items:flex-start;flex-direction:column}.hero{grid-template-columns:1fr;padding:35px 7%}.hero-icon{display:none}.cards{grid-template-columns:1fr}.formgrid{grid-template-columns:1fr}.wide{grid-column:auto}}
</style></head><body><div class="top"><span>☎ {{ shop.phone }} | {{ shop.address }}</span><span>{{ shop.shop_name }} · Owner: {{ shop.owner }}</span></div>
<nav><a class="brand" href="{{ url_for('home') }}"><span class="logo">✚</span>{{ shop.shop_name }}</a><div class="links">
<a href="{{ url_for('home') }}">{{ 'ہوم' if current_lang=='ur' else 'Home' }}</a><a href="{{ url_for('medicines') }}">{{ 'ادویات' if current_lang=='ur' else 'Medicines' }}</a>
{% if username %}{% if role in ['admin','distributor'] %}<a href="{{ url_for('dashboard') }}">Dashboard</a><a href="{{ url_for('staff_orders') }}">Orders</a>{% else %}<a href="{{ url_for('my_orders') }}">My Orders</a>{% endif %}<a href="{{ url_for('logout') }}">Logout</a>
{% else %}<a href="{{ url_for('login') }}">{{ 'لاگ اِن' if current_lang=='ur' else 'Login' }}</a><a href="{{ url_for('register') }}">{{ 'کسٹمر رجسٹریشن' if current_lang=='ur' else 'Customer Register' }}</a>{% endif %}
<a class="btn light" href="{{ url_for('toggle_language') }}">{{ 'English' if current_lang=='ur' else 'اردو' }}</a></div></nav><main>{% with messages=get_flashed_messages(with_categories=true) %}{% for cat,msg in messages %}<div class="alert {{ 'error' if cat=='error' else '' }}">{{ msg }}</div>{% endfor %}{% endwith %}{{ content|safe }}</main>
<footer><b>{{ shop.shop_name }}</b><br>{{ shop.address }} · {{ shop.phone }}<br>Please confirm medicine suitability with a qualified healthcare professional.</footer>
<script>
// Urdu interface translations. Language choice is saved in the Flask session.
if (document.documentElement.lang === 'ur') {
 const words = {
 'Home':'ہوم','Medicines':'ادویات','Dashboard':'ڈیش بورڈ','Orders':'آرڈرز','My Orders':'میرے آرڈرز','Logout':'لاگ آؤٹ','Login':'لاگ اِن','Customer Register':'کسٹمر رجسٹریشن','Your trusted healthcare store':'آپ کا قابلِ اعتماد میڈیکل اسٹور',
 'WELCOME TO SIKANDER MEDICAL STORE':'سکندر میڈیکل اسٹور میں خوش آمدید','Browse our medicine catalogue and send an order request. The store will confirm availability.':'ادویات کی فہرست دیکھیں اور آرڈر بھیجیں۔ اسٹور دستیابی کی تصدیق کرے گا۔','Browse Medicines':'ادویات دیکھیں','Our Services':'ہماری خدمات','Care · Service · Trust':'دیکھ بھال · خدمت · اعتماد','Medicine Catalogue':'ادویات کی فہرست','Browse products and availability.':'ادویات اور دستیابی دیکھیں۔','Orders & Billing':'آرڈرز اور بلنگ','Place an order and view its status.':'آرڈر دیں اور اس کی صورتحال دیکھیں۔','Secure Accounts':'محفوظ اکاؤنٹس','Separate customer and staff access.':'کسٹمر اور اسٹاف کے الگ اکاؤنٹس۔','Featured Medicines':'نمایاں ادویات','View all':'تمام دیکھیں','No medicines listed yet.':'ابھی کوئی دوا شامل نہیں کی گئی۔','No medicines found.':'کوئی دوا نہیں ملی۔',
 'Search medicines':'ادویات تلاش کریں','Search':'تلاش کریں','Customer Registration':'کسٹمر رجسٹریشن','Full name':'پورا نام','Username':'یوزر نیم','Phone':'فون نمبر','Address':'پتہ','Password (8 characters minimum)':'پاس ورڈ (کم از کم 8 حروف)','Password':'پاس ورڈ','Create account':'اکاؤنٹ بنائیں','New customer?':'نئے کسٹمر ہیں؟','Sign in':'لاگ اِن کریں','Login':'لاگ اِن','Medicine name':'دوا کا نام','Category':'قسم','Purchase price':'خریداری کی قیمت','Sale price':'فروخت کی قیمت','Stock':'اسٹاک','Details':'تفصیل','Save':'محفوظ کریں','Cancel':'منسوخ','Quantity':'تعداد','Order':'آرڈر','In stock':'دستیاب','Out of stock':'اسٹاک ختم',
 'Staff Dashboard':'اسٹاف ڈیش بورڈ','Listed medicines':'درج شدہ ادویات','Low stock (5 or less)':'کم اسٹاک (5 یا اس سے کم)','Pending orders':'زیرِ التوا آرڈرز','Medicine Inventory':'ادویات کا اسٹاک','Add Medicine':'دوا شامل کریں','Accounts':'اکاؤنٹس','Settings':'ترتیبات','Customer Orders':'کسٹمر آرڈرز','No medicines yet.':'ابھی کوئی دوا موجود نہیں۔','Edit':'ترمیم','Delete':'حذف کریں','Manage':'انتظام','Order':'آرڈر','Customer':'کسٹمر','Date':'تاریخ','Status':'حیثیت','Total':'کل رقم','Invoice':'انوائس','View':'دیکھیں','Manage Order':'آرڈر کا انتظام','Update status':'حیثیت اپ ڈیٹ کریں','Pending':'زیرِ التوا','Confirmed':'تصدیق شدہ','Ready':'تیار','Completed':'مکمل','Cancelled':'منسوخ','Print Invoice':'انوائس پرنٹ کریں','Store Settings':'اسٹور کی ترتیبات','Store name':'اسٹور کا نام','Owner':'مالک','Create staff account':'اسٹاف اکاؤنٹ بنائیں','Staff accounts':'اسٹاف اکاؤنٹس','Role':'کردار','Distributor':'ڈسٹری بیوٹر','Admin':'ایڈمن','Create':'بنائیں','Purchase':'خریداری','Sale':'فروخت','Actions':'عمل','No orders yet.':'ابھی کوئی آرڈر نہیں۔',
 'Account created. Please log in.':'اکاؤنٹ بن گیا۔ براہِ کرم لاگ اِن کریں۔','Incorrect username or password.':'یوزر نیم یا پاس ورڈ درست نہیں۔','Medicine added.':'دوا شامل ہوگئی۔','Medicine updated.':'دوا اپ ڈیٹ ہوگئی۔','Medicine deleted.':'دوا حذف ہوگئی۔','Order updated.':'آرڈر اپ ڈیٹ ہوگیا۔','Access denied':'رسائی کی اجازت نہیں۔','Page not found':'صفحہ نہیں ملا۔','Refresh and try again.':'صفحہ ریفریش کرکے دوبارہ کوشش کریں۔','Please confirm medicine suitability with a qualified healthcare professional.':'دوا کے استعمال سے پہلے مستند طبی ماہر سے مشورہ کریں۔'
 };
 const walker=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);const nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
 nodes.forEach(n=>{let value=n.nodeValue;for(const [en,ur] of Object.entries(words)){value=value.split(en).join(ur);}n.nodeValue=value;});
 document.querySelectorAll('input[placeholder],button,input[type=submit]').forEach(el=>{const key=el.placeholder||el.textContent||el.value;if(words[key]){if(el.placeholder)el.placeholder=words[key];else if(el.value)el.value=words[key];else el.textContent=words[key];}});
}
</script></body></html>
"""

def page(title, template, **kw):
    with connect() as db:
        shop = db.execute("SELECT * FROM settings WHERE id=1").fetchone()
    # IMPORTANT: pass csrf_token into the inner form template as well.
    content = render_template_string(template, csrf_token=csrf_token, shop=shop, **kw)
    return render_template_string(BASE, title=title, content=content, shop=shop,
        username=session.get("username"), role=session.get("role"),
        csrf_token=csrf_token, current_lang=session.get("lang", "en"))

HOME = r"""
<section class="hero"><div><small>WELCOME TO SIKANDER MEDICAL STORE</small><h1>Your trusted healthcare store</h1>
<p>Browse our medicine catalogue and send an order request. The store will confirm availability.</p>
<a class="btn" href="{{ url_for('medicines') }}">Browse Medicines</a></div><div class="hero-icon">✚</div></section>
<div class="heading"><h2>Our Services</h2><span class="muted">Care · Service · Trust</span></div>
<div class="cards"><div class="card"><div class="symbol">💊</div><h3>Medicine Catalogue</h3><p class="muted">Browse products and availability.</p></div>
<div class="card"><div class="symbol">🧾</div><h3>Orders & Billing</h3><p class="muted">Place an order and view its status.</p></div>
<div class="card"><div class="symbol">🔐</div><h3>Secure Accounts</h3><p class="muted">Separate customer and staff access.</p></div></div>
<div class="heading"><h2>Featured Medicines</h2><a class="btn light" href="{{ url_for('medicines') }}">View all</a></div>
<div class="cards">{% for m in items %}<div class="card"><div class="symbol">💊</div><h3>{{ m.name }}</h3><p class="muted">{{ m.category }}</p><b>{{ money(m.sale_price) }}</b><p>{{ 'In stock' if m.stock>0 else 'Out of stock' }}</p></div>{% else %}<div class="card">No medicines listed yet.</div>{% endfor %}</div>
"""
CATALOG = r"""
<div class="heading"><h2>Medicine Catalogue</h2></div><form class="panel" method="get" style="display:flex;gap:10px;margin-bottom:18px"><input name="q" value="{{ q }}" placeholder="Search medicines"><button class="btn">Search</button></form>
<div class="cards">{% for m in items %}<div class="card"><div class="symbol">💊</div><h3>{{ m.name }}</h3><p class="muted">{{ m.category }} · {{ m.details }}</p><b>{{ money(m.sale_price) }}</b><p>{{ 'In stock' if m.stock>0 else 'Out of stock' }} ({{ m.stock }})</p>
{% if m.stock>0 %}<form method="post" action="{{ url_for('place_order',mid=m.id) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="field"><label>Quantity</label><input type="number" name="quantity" min="1" max="{{ m.stock }}" value="1" required></div><button class="btn">Order</button></form>{% endif %}</div>{% else %}<div class="card">No medicines found.</div>{% endfor %}</div>
"""
LOGIN = r"""<div class="panel" style="max-width:460px;margin:35px auto"><h2>Login</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="field"><label>Username</label><input name="username" required></div><div class="field"><label>Password</label><input type="password" name="password" required></div><button class="btn" style="width:100%">Sign in</button></form><p class="muted">New customer? <a href="{{ url_for('register') }}">Create account</a></p></div>"""
REGISTER = r"""<div class="panel" style="max-width:520px;margin:30px auto"><h2>Customer Registration</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<div class="field"><label>Full name</label><input name="full_name" required></div><div class="field"><label>Username</label><input name="username" minlength="3" required></div>
<div class="field"><label>Phone</label><input name="phone" required></div><div class="field"><label>Address</label><textarea name="address"></textarea></div>
<div class="field"><label>Password (8 characters minimum)</label><input type="password" name="password" minlength="8" required></div><button class="btn">Create account</button></form></div>"""
MED_FORM = r"""<div class="panel"><h2>{{ heading }}</h2><form method="post" class="formgrid"><input type="hidden" name="_csrf" value="{{ csrf_token() }}">
<div class="field"><label>Medicine name</label><input name="name" required value="{{ item.name if item else '' }}"></div><div class="field"><label>Category</label><input name="category" value="{{ item.category if item else '' }}"></div>
<div class="field"><label>Purchase price</label><input type="number" min="0" step=".01" name="purchase_price" value="{{ item.purchase_price if item else 0 }}"></div><div class="field"><label>Sale price</label><input type="number" min="0" step=".01" name="sale_price" required value="{{ item.sale_price if item else 0 }}"></div>
<div class="field"><label>Stock</label><input type="number" min="0" name="stock" required value="{{ item.stock if item else 0 }}"></div><div class="field wide"><label>Details</label><textarea name="details">{{ item.details if item else '' }}</textarea></div>
<div class="wide actions"><button class="btn">Save</button><a class="btn light" href="{{ url_for('dashboard') }}">Cancel</a></div></form></div>"""
DASH = r"""<div class="heading"><div><h2>Staff Dashboard</h2><p class="muted">Signed in as {{ user }} · {{ role|title }}</p></div></div>
<div class="cards"><div class="card">Listed medicines<div class="stats">{{ count }}</div></div><div class="card">Low stock (5 or less)<div class="stats">{{ low }}</div></div><div class="card">Pending orders<div class="stats">{{ pending }}</div></div></div>
<div class="heading"><h2>Medicine Inventory</h2><div class="actions"><a class="btn" href="{{ url_for('add_medicine') }}">Add Medicine</a>{% if role=='admin' %}<a class="btn light" href="{{ url_for('accounts') }}">Accounts</a><a class="btn light" href="{{ url_for('settings') }}">Settings</a>{% endif %}<a class="btn light" href="{{ url_for('staff_orders') }}">Customer Orders</a>{% if role=='admin' %}<a class="btn light" href="{{ url_for('sales_report') }}">Sales Reports</a>{% endif %}</div></div>
<div class="tablewrap"><table><tr><th>Name</th><th>Category</th><th>Purchase</th><th>Sale</th><th>Stock</th><th>Actions</th></tr>{% for m in items %}<tr><td>{{ m.name }}</td><td>{{ m.category }}</td><td>{{ money(m.purchase_price) }}</td><td>{{ money(m.sale_price) }}</td><td>{{ m.stock }}</td><td><div class="actions"><a class="btn light" href="{{ url_for('edit_medicine',mid=m.id) }}">Edit</a>{% if role=='admin' %}<form method="post" action="{{ url_for('delete_medicine',mid=m.id) }}"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><button class="btn danger">Delete</button></form>{% endif %}</div></td></tr>{% else %}<tr><td colspan="6">No medicines yet.</td></tr>{% endfor %}</table></div>"""
ORDERS = r"""<div class="heading"><h2>{{ heading }}</h2></div><div class="tablewrap"><table><tr><th>Order</th><th>Customer</th><th>Phone / Address</th><th>Date</th><th>Status</th><th>Payment</th><th>Total</th><th>Invoice</th></tr>
{% for o in items %}<tr><td>#{{ o.id }}</td><td>{{ o.customer_name }}</td><td>{{ o.phone }}<br>{{ o.address }}</td><td>{{ o.created_at }}</td><td>{{ o.status }}</td><td>{{ o.payment_status or 'Unpaid' }}</td><td>{{ money(o.total) }}</td><td><a class="btn light" href="{{ url_for('invoice',oid=o.id) }}">View</a>{% if staff %}<a class="btn" href="{{ url_for('manage_order',oid=o.id) }}">Manage</a>{% endif %}</td></tr>{% else %}<tr><td colspan="8">No orders yet.</td></tr>{% endfor %}</table></div>"""
MANAGE = r"""<div class="panel"><h2>Manage Order #{{ order.id }}</h2><p>{{ order.customer_name }} · {{ order.phone }} · {{ order.address }}</p><div class="tablewrap"><table><tr><th>Medicine</th><th>Qty</th><th>Unit price</th><th>Total</th></tr>{% for x in lines %}<tr><td>{{ x.medicine_name }}</td><td>{{ x.quantity }}</td><td>{{ money(x.unit_price) }}</td><td>{{ money(x.line_total) }}</td></tr>{% endfor %}</table></div><h3>Total: {{ money(order.total) }}</h3>
<form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="field"><label>Order status</label><select name="status">{% for s in statuses %}<option {{ 'selected' if order.status==s else '' }}>{{ s }}</option>{% endfor %}</select></div><div class="field"><label>Payment status</label><select name="payment_status"><option value="Unpaid" {{ 'selected' if order.payment_status=='Unpaid' else '' }}>Unpaid</option><option value="Paid" {{ 'selected' if order.payment_status=='Paid' else '' }}>Paid</option></select></div><button class="btn">Save Order</button></form></div>"""
INVOICE = r"""<div class="panel" style="max-width:800px;margin:auto"><div class="actions" style="justify-content:space-between"><h2>{{ shop.shop_name }}</h2><button class="btn light" onclick="window.print()">Print Invoice</button></div><p>{{ shop.address }} · {{ shop.phone }}</p><hr><h2>Invoice {{ inv.invoice_number if inv else 'Pending confirmation' }}</h2>
<p>Order #{{ order.id }} · {{ order.created_at }}</p><p>Customer: {{ order.customer_name }} · {{ order.phone }}</p><p>Address: {{ order.address }}</p>
<div class="tablewrap"><table><tr><th>Item</th><th>Qty</th><th>Rate</th><th>Amount</th></tr>{% for x in lines %}<tr><td>{{ x.medicine_name }}</td><td>{{ x.quantity }}</td><td>{{ money(x.unit_price) }}</td><td>{{ money(x.line_total) }}</td></tr>{% endfor %}</table></div><h2 style="text-align:right">Total: {{ money(order.total) }}</h2><p>Order status: {{ order.status }}</p><p>Payment status: <b>{{ order.payment_status or 'Unpaid' }}</b></p></div>"""
ACCOUNTS = r"""<div class="cards"><div class="panel"><h2>Create staff account</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="field"><label>Username</label><input name="username" minlength="3" required></div><div class="field"><label>Password</label><input name="password" type="password" minlength="8" required></div><div class="field"><label>Role</label><select name="role"><option value="distributor">Distributor</option><option value="admin">Admin</option></select></div><button class="btn">Create</button></form></div><div class="panel"><h2>Staff accounts</h2>{% for u in users %}<p>{{ u.username }} — {{ u.role }}</p>{% endfor %}</div></div>"""
SETTINGS = r"""<div class="panel"><h2>Store Settings</h2><form method="post"><input type="hidden" name="_csrf" value="{{ csrf_token() }}"><div class="field"><label>Store name</label><input name="shop_name" value="{{ row.shop_name }}" required></div><div class="field"><label>Phone</label><input name="phone" value="{{ row.phone }}" required></div><div class="field"><label>Address</label><input name="address" value="{{ row.address }}"></div><div class="field"><label>Owner</label><input name="owner" value="{{ row.owner }}"></div><button class="btn">Save</button></form></div>"""

@app.route("/language")
def toggle_language():
    session["lang"] = "ur" if session.get("lang", "en") == "en" else "en"
    return redirect(request.referrer or url_for("home"))

@app.route("/")
def home():
    with connect() as db:
        items = db.execute("SELECT * FROM medicines ORDER BY id DESC LIMIT 6").fetchall()
    return page("Home", HOME, items=items, money=money)

@app.route("/medicines")
def medicines():
    q = request.args.get("q", "").strip()
    with connect() as db:
        items = db.execute("SELECT * FROM medicines WHERE name LIKE ? OR category LIKE ? ORDER BY name",
                           (f"%{q}%", f"%{q}%")).fetchall()
    return page("Medicines", CATALOG, items=items, q=q, money=money)

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        check_csrf()
        name=request.form.get("full_name","").strip()
        username=request.form.get("username","").strip()
        phone=request.form.get("phone","").strip()
        address=request.form.get("address","").strip()
        password=request.form.get("password","")
        if not name or len(username)<3 or not phone or len(password)<8:
            flash("Fill all required fields. Username needs 3 characters and password 8.","error")
            return redirect(url_for("register"))
        try:
            with connect() as db:
                db.execute("INSERT INTO users(username,password_hash,role,full_name,phone,address,created_at) VALUES(?,?,?,?,?,?,?)",
                           (username,generate_password_hash(password),"customer",name,phone,address,now()))
            flash("Account created. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already exists.","error")
    return page("Customer Registration",REGISTER)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        check_csrf()
        with connect() as db:
            user=db.execute("SELECT * FROM users WHERE username=?",(request.form.get("username","").strip(),)).fetchone()
        if user and check_password_hash(user["password_hash"],request.form.get("password","")):
            session.clear()
            session.update(user_id=user["id"],username=user["username"],role=user["role"])
            return redirect(url_for("my_orders" if user["role"]=="customer" else "dashboard"))
        flash("Incorrect username or password.","error")
    return page("Login",LOGIN)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

@app.route("/order/<int:mid>", methods=["POST"])
@roles_required("customer")
def place_order(mid):
    check_csrf()
    try:
        qty=int(request.form.get("quantity","1"))
        if qty<1: raise ValueError
    except ValueError:
        flash("Enter a valid quantity.","error")
        return redirect(url_for("medicines"))
    with connect() as db:
        med=db.execute("SELECT * FROM medicines WHERE id=?",(mid,)).fetchone()
        user=db.execute("SELECT * FROM users WHERE id=?",(session["user_id"],)).fetchone()
        if not med or med["stock"]<qty:
            flash("Requested quantity is not available.","error")
            return redirect(url_for("medicines"))
        total=round(float(med["sale_price"])*qty,2)
        cur=db.execute("INSERT INTO orders(customer_id,customer_name,phone,address,total,created_at) VALUES(?,?,?,?,?,?)",
                        (user["id"],user["full_name"] or user["username"],user["phone"],user["address"],total,now()))
        oid=cur.lastrowid
        db.execute("INSERT INTO order_items(order_id,medicine_id,medicine_name,quantity,unit_price,line_total) VALUES(?,?,?,?,?,?)",
                   (oid,med["id"],med["name"],qty,med["sale_price"],total))
    flash(f"Order #{oid} submitted. Store will confirm availability.")
    return redirect(url_for("my_orders"))

@app.route("/my-orders")
@roles_required("customer")
def my_orders():
    with connect() as db:
        items=db.execute("SELECT * FROM orders WHERE customer_id=? ORDER BY id DESC",(session["user_id"],)).fetchall()
    return page("My Orders",ORDERS,heading="My Orders",items=items,staff=False,money=money)

@app.route("/dashboard")
@roles_required("admin","distributor")
def dashboard():
    with connect() as db:
        items=db.execute("SELECT * FROM medicines ORDER BY id DESC").fetchall()
        count=db.execute("SELECT COUNT(*) FROM medicines").fetchone()[0]
        low=db.execute("SELECT COUNT(*) FROM medicines WHERE stock<=5").fetchone()[0]
        pending=db.execute("SELECT COUNT(*) FROM orders WHERE status='Pending'").fetchone()[0]
    return page("Dashboard",DASH,items=items,count=count,low=low,pending=pending,
                user=session["username"],role=session["role"],money=money)

@app.route("/medicine/add",methods=["GET","POST"])
@roles_required("admin","distributor")
def add_medicine():
    if request.method=="POST":
        check_csrf()
        name=request.form.get("name","").strip()
        try:
            purchase=float(request.form.get("purchase_price","0")); sale=float(request.form.get("sale_price","0")); stock=int(request.form.get("stock","0"))
            if not name or min(purchase,sale,stock)<0: raise ValueError
        except ValueError:
            flash("Enter valid medicine details and non-negative amounts.","error")
            return redirect(url_for("add_medicine"))
        with connect() as db:
            db.execute("INSERT INTO medicines(name,category,purchase_price,sale_price,stock,details,added_by,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                       (name,request.form.get("category","").strip(),purchase,sale,stock,request.form.get("details","").strip(),session["user_id"],now()))
        flash("Medicine added.")
        return redirect(url_for("dashboard"))
    return page("Add Medicine",MED_FORM,heading="Add Medicine",item=None)

@app.route("/medicine/edit/<int:mid>",methods=["GET","POST"])
@roles_required("admin","distributor")
def edit_medicine(mid):
    with connect() as db:
        item=db.execute("SELECT * FROM medicines WHERE id=?",(mid,)).fetchone()
        if not item: abort(404)
        if request.method=="POST":
            check_csrf()
            name=request.form.get("name","").strip()
            try:
                purchase=float(request.form.get("purchase_price","0")); sale=float(request.form.get("sale_price","0")); stock=int(request.form.get("stock","0"))
                if not name or min(purchase,sale,stock)<0: raise ValueError
            except ValueError:
                flash("Invalid medicine details.","error")
                return redirect(url_for("edit_medicine",mid=mid))
            db.execute("UPDATE medicines SET name=?,category=?,purchase_price=?,sale_price=?,stock=?,details=?,updated_at=? WHERE id=?",
                       (name,request.form.get("category","").strip(),purchase,sale,stock,request.form.get("details","").strip(),now(),mid))
            flash("Medicine updated.")
            return redirect(url_for("dashboard"))
    return page("Edit Medicine",MED_FORM,heading="Edit Medicine",item=item)

@app.route("/medicine/delete/<int:mid>",methods=["POST"])
@roles_required("admin")
def delete_medicine(mid):
    check_csrf()
    with connect() as db: db.execute("DELETE FROM medicines WHERE id=?",(mid,))
    flash("Medicine deleted.")
    return redirect(url_for("dashboard"))

@app.route("/staff/orders")
@roles_required("admin","distributor")
def staff_orders():
    with connect() as db: items=db.execute("SELECT * FROM orders ORDER BY id DESC").fetchall()
    return page("Customer Orders",ORDERS,heading="Customer Orders",items=items,staff=True,money=money)

@app.route("/staff/order/<int:oid>",methods=["GET","POST"])
@roles_required("admin","distributor")
def manage_order(oid):
    statuses=["Pending","Confirmed","Ready","Completed","Cancelled"]
    with connect() as db:
        order=db.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()
        if not order: abort(404)
        if request.method=="POST":
            check_csrf(); status=request.form.get("status","")
            payment_status=request.form.get("payment_status", "Unpaid")
            if status not in statuses or payment_status not in ("Paid", "Unpaid"): abort(400)
            db.execute("UPDATE orders SET status=?, payment_status=? WHERE id=?",(status,payment_status,oid))
            if status in ("Confirmed","Ready","Completed"):
                exists=db.execute("SELECT id FROM invoices WHERE order_id=?",(oid,)).fetchone()
                if not exists:
                    db.execute("INSERT INTO invoices(order_id,invoice_number,issued_at) VALUES(?,?,?)",
                               (oid,f"SMS-{datetime.now():%Y%m%d}-{oid:05d}",now()))
            flash("Order updated.")
            return redirect(url_for("manage_order",oid=oid))
        lines=db.execute("SELECT * FROM order_items WHERE order_id=?",(oid,)).fetchall()
    return page("Manage Order",MANAGE,order=order,lines=lines,statuses=statuses,money=money)

@app.route("/invoice/<int:oid>")
@login_required
def invoice(oid):
    with connect() as db:
        order=db.execute("SELECT * FROM orders WHERE id=?",(oid,)).fetchone()
        if not order: abort(404)
        if session.get("role") not in ("admin","distributor") and order["customer_id"]!=session["user_id"]: abort(403)
        lines=db.execute("SELECT * FROM order_items WHERE order_id=?",(oid,)).fetchall()
        inv=db.execute("SELECT * FROM invoices WHERE order_id=?",(oid,)).fetchone()
    return page("Invoice",INVOICE,order=order,lines=lines,inv=inv,money=money)

@app.route("/reports")
@roles_required("admin")
def sales_report():
    with connect() as db:
        total_orders = db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
        total_sales = db.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE status!='Cancelled'").fetchone()[0]
        paid_sales = db.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE payment_status='Paid' AND status!='Cancelled'").fetchone()[0]
        unpaid_sales = db.execute("SELECT COALESCE(SUM(total),0) FROM orders WHERE payment_status!='Paid' AND status!='Cancelled'").fetchone()[0]
        daily = db.execute("SELECT substr(created_at,1,10) AS day, COUNT(*) AS orders_count, COALESCE(SUM(CASE WHEN status!='Cancelled' THEN total ELSE 0 END),0) AS sales FROM orders GROUP BY substr(created_at,1,10) ORDER BY day DESC LIMIT 31").fetchall()
    template = r'''<div class="heading"><div><h2>Sales Reports</h2><p class="muted">Order and payment summary</p></div><a class="btn light" href="{{ url_for('dashboard') }}">Back to Dashboard</a></div>
    <div class="cards"><div class="card">Total orders<div class="stats">{{ total_orders }}</div></div><div class="card">Total sales<div class="stats">{{ money(total_sales) }}</div></div><div class="card">Paid sales<div class="stats">{{ money(paid_sales) }}</div></div><div class="card">Unpaid sales<div class="stats">{{ money(unpaid_sales) }}</div></div></div>
    <div class="heading"><h2>Daily sales (last 31 days with orders)</h2></div><div class="tablewrap"><table><tr><th>Date</th><th>Orders</th><th>Sales</th></tr>{% for d in daily %}<tr><td>{{ d.day }}</td><td>{{ d.orders_count }}</td><td>{{ money(d.sales) }}</td></tr>{% else %}<tr><td colspan="3">No sales data yet.</td></tr>{% endfor %}</table></div>'''
    return page("Sales Reports", template, total_orders=total_orders, total_sales=total_sales, paid_sales=paid_sales, unpaid_sales=unpaid_sales, daily=daily, money=money)

@app.route("/accounts",methods=["GET","POST"])
@roles_required("admin")
def accounts():
    if request.method=="POST":
        check_csrf()
        username=request.form.get("username","").strip(); password=request.form.get("password",""); role=request.form.get("role","")
        if len(username)<3 or len(password)<8 or role not in ("admin","distributor"):
            flash("Username 3+ chars, password 8+ chars and valid staff role required.","error")
        else:
            try:
                with connect() as db: db.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",(username,generate_password_hash(password),role,now()))
                flash("Staff account created.")
            except sqlite3.IntegrityError: flash("Username already exists.","error")
        return redirect(url_for("accounts"))
    with connect() as db: users=db.execute("SELECT username,role FROM users WHERE role!='customer' ORDER BY username").fetchall()
    return page("Accounts",ACCOUNTS,users=users)

@app.route("/settings",methods=["GET","POST"])
@roles_required("admin")
def settings():
    with connect() as db:
        if request.method=="POST":
            check_csrf()
            db.execute("UPDATE settings SET shop_name=?,phone=?,address=?,owner=? WHERE id=1",
                       (request.form.get("shop_name","").strip(),request.form.get("phone","").strip(),request.form.get("address","").strip(),request.form.get("owner","").strip()))
            flash("Settings saved.")
            return redirect(url_for("settings"))
        row=db.execute("SELECT * FROM settings WHERE id=1").fetchone()
    return page("Settings",SETTINGS,row=row)

@app.errorhandler(403)
def forbidden(_e): return page("Access denied",'<div class="panel"><h2>Access denied</h2><a class="btn" href="/">Home</a></div>'),403
@app.errorhandler(404)
def missing(_e): return page("Not found",'<div class="panel"><h2>Page not found</h2><a class="btn" href="/">Home</a></div>'),404
@app.errorhandler(400)
def bad_request(_e): return page("Bad request",'<div class="panel"><h2>Bad request</h2><p>Refresh and try again.</p></div>'),400

if __name__ == "__main__":
    init_db()
    print("Sikander Medical Store starting...")
    print("Open http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
