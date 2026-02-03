spicy_add_analyzer(
    NAME NAT
    PACKAGE_NAME spicy-nat
    SOURCES nat.spicy nat.evt natpmp.spicy pcp.spicy
    MODULES NAT NATPMP PCP)
