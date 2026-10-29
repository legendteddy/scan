public sealed record PaymentMessage(
    string MessageId,
    string AccountId,
    decimal Amount,
    long Sequence,
    decimal ReportedBalance
);

public sealed class PaymentWorker
{
    private readonly Broker broker;
    private readonly Payments payments;
    private readonly Accounts accounts;
    private readonly Audit audit;

    public PaymentWorker(Broker broker, Payments payments, Accounts accounts, Audit audit)
    {
        this.broker = broker;
        this.payments = payments;
        this.accounts = accounts;
        this.audit = audit;
    }

    public async Task Handle(PaymentMessage message)
    {
        await broker.Ack(message.MessageId);
        await payments.Charge(message.AccountId, message.Amount);

        var account = await accounts.Load(message.AccountId);
        account.Balance = message.ReportedBalance;
        account.LastSequence = message.Sequence;
        await accounts.Save(account);

        await audit.Record($"charged:{message.MessageId}");
    }

    public Task Retry(PaymentMessage message) => Handle(message);
}
