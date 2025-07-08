"""Money value object."""

from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

from app.core.domain.base import ValueObject
from app.core.errors import ValidationError


class Money(ValueObject):
    """Money value object with currency and arithmetic operations."""

    # Supported currencies
    SUPPORTED_CURRENCIES = {
        "CAD",
        "USD",
        "EUR",
        "GBP",
        "JPY",
        "CNY",
        "AUD",
        "MXN",
        "BRL",
        "INR",
    }

    def __init__(self, amount: Decimal | float | int | str, currency: str = "CAD"):
        """
        Initialize and validate money amount and currency.

        Args:
            amount: Money amount (will be converted to Decimal)
            currency: ISO 4217 currency code (default: "CAD")

        Raises:
            ValidationError: If amount or currency is invalid
        """
        self.amount = self._validate_amount(amount)
        self.currency = self._validate_currency(currency)

    def _validate_amount(self, amount: Decimal | float | int | str) -> Decimal:
        """Validate and convert amount to Decimal."""
        try:
            # Convert to string first to handle commas
            if isinstance(amount, str):
                amount = amount.replace(",", "").strip()

            # Convert to Decimal
            decimal_amount = Decimal(str(amount))

            # Round to appropriate decimal places based on currency
            if self._get_currency_decimals(getattr(self, "currency", "CAD")) == 0:
                return decimal_amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
            return decimal_amount.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        except (InvalidOperation, ValueError, TypeError):
            raise ValidationError("Invalid money amount")

    def _validate_currency(self, currency: str) -> str:
        """Validate currency code."""
        if not currency or not isinstance(currency, str):
            raise ValidationError("Currency cannot be empty")

        if len(currency) != 3:
            raise ValidationError("Currency must be a 3-letter ISO 4217 code")

        currency = currency.upper()

        if currency not in self.SUPPORTED_CURRENCIES:
            raise ValidationError(f"Unsupported currency: {currency}")

        return currency

    def _get_currency_decimals(self, currency: str) -> int:
        """Get number of decimal places for currency."""
        # JPY and some others don't use decimal places
        no_decimal_currencies = {"JPY", "KRW", "VND"}
        return 0 if currency in no_decimal_currencies else 2

    @staticmethod
    def validate_amount_format(amount: str | int | float) -> bool:
        """
        Static method to validate amount format.

        Args:
            amount: Amount to validate

        Returns:
            bool: True if amount format is valid
        """
        try:
            if isinstance(amount, str):
                amount = amount.replace(",", "").strip()
            Decimal(str(amount))
            return True
        except (InvalidOperation, ValueError, TypeError):
            return False

    @staticmethod
    def validate_currency_code(currency: str) -> bool:
        """
        Static method to validate currency code.

        Args:
            currency: Currency code to validate

        Returns:
            bool: True if currency code is valid
        """
        return (
            isinstance(currency, str)
            and len(currency) == 3
            and currency.upper() in Money.SUPPORTED_CURRENCIES
        )

    def __add__(self, other: "Money") -> "Money":
        """Add two money values."""
        if not isinstance(other, Money):
            raise TypeError("Can only add Money to Money")

        if self.currency != other.currency:
            raise ValueError("Cannot add different currencies")

        return Money(self.amount + other.amount, self.currency)

    def __sub__(self, other: "Money") -> "Money":
        """Subtract two money values."""
        if not isinstance(other, Money):
            raise TypeError("Can only subtract Money from Money")

        if self.currency != other.currency:
            raise ValueError("Cannot subtract different currencies")

        return Money(self.amount - other.amount, self.currency)

    def __mul__(self, other: int | float | Decimal) -> "Money":
        """Multiply money by a scalar."""
        if not isinstance(other, int | float | Decimal):
            raise TypeError("Can only multiply Money by a number")

        return Money(self.amount * Decimal(str(other)), self.currency)

    def __rmul__(self, other: int | float | Decimal) -> "Money":
        """Right multiply (allows number * money)."""
        return self.__mul__(other)

    def __truediv__(self, other: int | float | Decimal) -> "Money":
        """Divide money by a scalar."""
        if not isinstance(other, int | float | Decimal):
            raise TypeError("Can only divide Money by a number")

        if other == 0:
            raise ValueError("Cannot divide by zero")

        return Money(self.amount / Decimal(str(other)), self.currency)

    def __floordiv__(self, other: int | float | Decimal) -> "Money":
        """Floor division of money by a scalar."""
        if not isinstance(other, int | float | Decimal):
            raise TypeError("Can only divide Money by a number")

        if other == 0:
            raise ValueError("Cannot divide by zero")

        return Money(self.amount // Decimal(str(other)), self.currency)

    def __mod__(self, other: int | float | Decimal) -> "Money":
        """Modulo operation with money."""
        if not isinstance(other, int | float | Decimal):
            raise TypeError("Can only use modulo with Money and a number")

        return Money(self.amount % Decimal(str(other)), self.currency)

    def __neg__(self) -> "Money":
        """Negate money value."""
        return Money(-self.amount, self.currency)

    def __abs__(self) -> "Money":
        """Absolute value of money."""
        return Money(abs(self.amount), self.currency)

    def __lt__(self, other: "Money") -> bool:
        """Less than comparison."""
        if not isinstance(other, Money):
            return NotImplemented

        if self.currency != other.currency:
            raise ValueError("Cannot compare different currencies")

        return self.amount < other.amount

    def __le__(self, other: "Money") -> bool:
        """Less than or equal comparison."""
        if not isinstance(other, Money):
            return NotImplemented

        if self.currency != other.currency:
            raise ValueError("Cannot compare different currencies")

        return self.amount <= other.amount

    def __gt__(self, other: "Money") -> bool:
        """Greater than comparison."""
        if not isinstance(other, Money):
            return NotImplemented

        if self.currency != other.currency:
            raise ValueError("Cannot compare different currencies")

        return self.amount > other.amount

    def __ge__(self, other: "Money") -> bool:
        """Greater than or equal comparison."""
        if not isinstance(other, Money):
            return NotImplemented

        if self.currency != other.currency:
            raise ValueError("Cannot compare different currencies")

        return self.amount >= other.amount

    def is_zero(self) -> bool:
        """Check if amount is zero."""
        return self.amount == 0

    def is_positive(self) -> bool:
        """Check if amount is positive."""
        return self.amount > 0

    def is_negative(self) -> bool:
        """Check if amount is negative."""
        return self.amount < 0

    def round_to_currency(self) -> "Money":
        """Round amount to appropriate decimal places for currency."""
        decimals = self._get_currency_decimals(self.currency)
        if decimals == 0:
            rounded_amount = self.amount.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
        else:
            rounded_amount = self.amount.quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )

        return Money(rounded_amount, self.currency)

    def allocate(self, ratios: list) -> list["Money"]:
        """
        Allocate money according to ratios (useful for splitting bills).

        Args:
            ratios: List of ratios (will be normalized)

        Returns:
            List of Money objects
        """
        if not ratios or any(r < 0 for r in ratios):
            raise ValueError("All ratios must be positive")

        total_ratio = sum(ratios)
        if total_ratio == 0:
            raise ValueError("Total ratio cannot be zero")

        allocated = []
        remainder = self.amount

        for i, ratio in enumerate(ratios):
            if i == len(ratios) - 1:  # Last allocation gets remainder
                allocated.append(Money(remainder, self.currency))
            else:
                allocation = (
                    self.amount * Decimal(str(ratio)) / Decimal(str(total_ratio))
                ).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
                allocated.append(Money(allocation, self.currency))
                remainder -= allocation

        return allocated

    def format(self, include_currency: bool = True, symbol_only: bool = False) -> str:
        """
        Format money for display.

        Args:
            include_currency: Whether to include currency info
            symbol_only: Use symbol instead of currency code

        Returns:
            str: Formatted money string
        """
        # Currency symbols
        symbols = {
            "CAD": "$",
            "USD": "$",
            "EUR": "€",
            "GBP": "£",
            "JPY": "¥",
            "CNY": "¥",
            "AUD": "$",
            "MXN": "$",
            "BRL": "R$",
            "INR": "₹",
        }

        # Format amount based on currency decimals
        decimals = self._get_currency_decimals(self.currency)
        if decimals == 0:
            formatted_amount = f"{self.amount:,.0f}"
        else:
            formatted_amount = f"{self.amount:,.2f}"

        if not include_currency:
            return formatted_amount

        symbol = symbols.get(self.currency, self.currency)

        if symbol_only:
            return f"{symbol}{formatted_amount}"
        if self.currency in ["CAD", "USD", "AUD", "MXN"]:
            # Disambiguate dollar currencies
            return f"{symbol}{formatted_amount} {self.currency}"
        return f"{symbol}{formatted_amount}"

    def __str__(self) -> str:
        """String representation."""
        return self.format()

    def __eq__(self, other) -> bool:
        """Check equality."""
        if not isinstance(other, Money):
            return False
        return self.amount == other.amount and self.currency == other.currency

    def __hash__(self) -> int:
        """Return hash for use in sets/dicts."""
        return hash((self.amount, self.currency))

    def __repr__(self) -> str:
        """Detailed string representation for debugging."""
        return f"Money(amount={self.amount}, currency='{self.currency}')"
