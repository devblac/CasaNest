# contracts/home_circle/app.py (Modern Pattern)
from beaker import (
    Application,
    Authorize,
    ApplicationState,
    precompiled,
    external,
)
from pyteal import *

class HomeCircleState:
    target = ApplicationState(default=Int(0), static=True)  # Immutable after creation
    contribution = ApplicationState(default=Int(0), desc="Monthly in microALGO")
    members = ApplicationState(default=Bytes(""), desc="Base32 addresses")
    balance = ApplicationState(default=Int(0), desc="Total funds (microALGO)")
    active = ApplicationState(default=Int(1), desc="1=active, 0=closed")

app = Application("HomeCircle", state=HomeCircleState())

@app.create(authorize=Authorize.only(Global.creator_address()))
def create(self, target: abi.Uint64, monthly: abi.Uint64):
    """Initialize circle (admin only)"""
    return Seq(
        app.state.target.set(target.get()), ## Target amount. e.g. $100,000
        app.state.contribution.set(monthly.get()), ## Monthly contribution required. e.g. $1,000 
        app.state.active.set(Int(1)) # Activate circle
    )

@precompiled  # Security: Isolated validation logic
def validate_payment(sender: Expr, amount: Expr) -> Expr:
    """Ensure payment matches required monthly contribution"""
    return And(
        app.state.active == Int(1),
        amount == app.state.contribution,
        Txn.rekey_to() == Global.zero_address(),  # Prevent rekey attacks
    )

@app.external(authorize=Authorize.holds_token(validate_payment))
def join(self, payment: abi.PaymentTransaction):
    """User joins the savings circle by sending exact contribution amount"""
    return Seq(
        app.state.balance.set(app.state.balance + payment.get().amount()),
        app.state.members.set(Concat(app.state.members, Txn.sender()))
    )