"""Integração opcional com Mercado Pago para o MotoJá SP.
Sem MP_ACCESS_TOKEN, os métodos retornam um estado de demonstração."""
import json
import os
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

ACCESS_TOKEN=os.getenv('MP_ACCESS_TOKEN','')
PUBLIC_KEY=os.getenv('MP_PUBLIC_KEY','')
API='https://api.mercadopago.com'

def mp_post(path,payload):
    if not ACCESS_TOKEN: return None
    raw=json.dumps(payload).encode()
    req=Request(API+path,data=raw,headers={'Authorization':f'Bearer {ACCESS_TOKEN}','Content-Type':'application/json'},method='POST')
    try:
        with urlopen(req,timeout=15) as response: return json.loads(response.read().decode())
    except (HTTPError,URLError,TimeoutError): return None

def create_pix(amount,description,email):
    if not ACCESS_TOKEN:
        return {'provider':'demo','status':'demo_pending','amount':amount,'message':'Configure MP_ACCESS_TOKEN para gerar Pix real.'}
    return mp_post('/v1/payments',{'transaction_amount':round(float(amount),2),'description':description,'payment_method_id':'pix','payer':{'email':email or 'cliente@example.com'}}) or {'provider':'mercado_pago','status':'error','message':'Não foi possível criar o Pix.'}

def get_payment(payment_id):
    if not ACCESS_TOKEN or not payment_id: return None
    req=Request(API+f'/v1/payments/{payment_id}',headers={'Authorization':f'Bearer {ACCESS_TOKEN}'},method='GET')
    try:
        with urlopen(req,timeout=15) as response: return json.loads(response.read().decode())
    except (HTTPError,URLError,TimeoutError): return None

def create_preference(amount,description):
    if not ACCESS_TOKEN:
        return {'provider':'demo','status':'demo_pending','amount':amount,'message':'Configure MP_ACCESS_TOKEN para gerar checkout real.'}
    return mp_post('/checkout/preferences',{'items':[{'title':description,'quantity':1,'currency_id':'BRL','unit_price':round(float(amount),2)}]}) or {'provider':'mercado_pago','status':'error','message':'Não foi possível criar o checkout.'}
