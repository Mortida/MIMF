class PolicyError(Exception):
    """
    Base exception for all policy-related failures.
    """

    pass


class PolicyViolation(PolicyError):
    """
    Raised when a policy explicitly denies an operation.
    """

    pass


class PolicyConfigurationError(PolicyError):
    """
    Raised when policies are misconfigured or invalid.
    """

    pass
