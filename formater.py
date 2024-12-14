class Formater:
    @staticmethod
    def format_without_number(ttl: int, address: str, time: int):
        print(f"{ttl:>2} {address:<15} {time:>3} ms")

    @staticmethod
    def format_with_number(ttl: int, address: str, time: int, number: int):
        print(f"{ttl:>2} {address:<15} {time:>3} ms {number}")

    @staticmethod
    def format_empty(ttl: int):
        print(f"{ttl:>2} *")