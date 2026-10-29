import time


def charge_with_retry(client, account_id, amount):
    delays = (0.1, 0.2, 0.4)
    for attempt, delay in enumerate(delays, start=1):
        try:
            return client.charge(account_id=account_id, amount=amount)
        except TimeoutError:
            if attempt == len(delays):
                raise
            time.sleep(delay)


def send_receipt(mailer, address, receipt):
    try:
        mailer.send(address, receipt)
    except Exception:
        # Receipt delivery is deliberately best-effort and does not change charge status.
        return False
    return True
