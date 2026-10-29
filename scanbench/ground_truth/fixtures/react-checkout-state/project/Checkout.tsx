import React, { useEffect, useState } from "react";

type Api = {
  quote(quantity: number): Promise<{ total: number }>;
  placeOrder(input: { quantity: number }): Promise<{ id: string }>;
};

export function Checkout({ api }: { api: Api }) {
  const [quantity, setQuantity] = useState(1);
  const [total, setTotal] = useState(0);
  const [status, setStatus] = useState("");

  useEffect(() => {
    api.quote(quantity).then((quote) => setTotal(quote.total));
  }, [api, quantity]);

  async function submit() {
    setStatus("Submitting order");
    const order = await api.placeOrder({ quantity });
    setStatus(`Order ${order.id} created`);
  }

  return (
    <section>
      <h1>Checkout</h1>
      <input
        type="number"
        min={1}
        value={quantity}
        onChange={(event) => setQuantity(Number(event.target.value))}
      />
      <button type="button" onClick={() => setQuantity((value) => value + 1)}>
        Increase quantity
      </button>
      <p>Total: {total}</p>
      <div role="status" aria-live="polite">{status}</div>
      <div className="place-order" onClick={submit}>Place order</div>
    </section>
  );
}
