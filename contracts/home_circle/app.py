from beaker import (
    Application, 
    Authorize, 
    GlobalStateValue, 
    AccountStateValue,
    external
)
from pyteal import *
from .utils import generate_secure_randomness
from interfaces.randomness import IRandomnessOracle

class HomeCircleState:
    # Global state
    target_amount = GlobalStateValue(stack_type=TealType.uint64)
    monthly_contribution = GlobalStateValue(stack_type=TealType.uint64)
    members = GlobalStateValue(stack_type=TealType.bytes, desc="CSV of member addresses")
    balance = GlobalStateValue(stack_type=TealType.uint64)
    is_active = GlobalStateValue(stack_type=TealType.uint64)

    # Per-account state
    user_contribution = AccountStateValue(stack_type=TealType.uint64)

class HomeCircle(Application):
    def __init__(self, oracle: IRandomnessOracle):
        self.state = HomeCircleState()
        self.oracle = oracle

        # Security: Explicit authorize all methods
        self.create = Authorize.only(Global.creator_address())(self.create)
        self.join = Authorize.holds_token(self.state.monthly_contribution)(self.join)

    @external(authorize=Authorize.only(Global.creator_address()))
    def create(self, target: abi.Uint64, monthly: abi.Uint64):
        """Initialize a new savings circle (admin only)"""
        return Seq(
            self.state.target_amount.set(target.get()),
            self.state.monthly_contribution.set(monthly.get()),
            self.state.is_active.set(Int(1))
        )

    @external
    def join(self, payment: abi.PaymentTransaction):
        """Join circle with required payment"""
        return Seq(
            Assert(self.state.is_active == Int(1)),
            Assert(payment.get().amount() == self.state.monthly_contribution),
            self.state.balance.set(self.state.balance + payment.amount()),
            self.state.members.set(Concat(self.state.members, Txn.sender())),
            self.state.user_contribution[Txn.sender()].set(
                self.state.user_contribution[Txn.sender()] + payment.amount()
            )
        )

    @external(authorize=Authorize.only(Global.creator_address()))
    def select_winner(self):
        """Select winner using secure oracle (admin only)"""
        return Seq(
            self.oracle.validate(),
            winner_idx := self.oracle.get_random_index(self.state.members.length()),
            winner := Substring(self.state.members, winner_idx*32, (winner_idx+1)*32),
            InnerTxnBuilder.ExecuteMethodCall(
                app_id=0,
                method_signature="pay(account,uint64)void",
                args=[winner, self.state.balance],
                extra_fields={TxnField.fee: Int(0)}
            ),
            self.state.balance.set(0),
            self.state.is_active.set(0)
        )