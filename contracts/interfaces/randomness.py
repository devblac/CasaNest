# interfaces/randomness.py
from abc import ABC, abstractmethod
from pyteal import *

class IRandomnessOracle(ABC):
    @abstractmethod
    def validate(self) -> Expr:
        pass
    
    @abstractmethod
    def get_random_index(self, max_value: Expr) -> Expr:
        pass