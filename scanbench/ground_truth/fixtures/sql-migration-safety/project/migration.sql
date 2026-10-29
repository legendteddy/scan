BEGIN;

ALTER TABLE customers DROP COLUMN legacy_account_number;
ALTER TABLE orders ALTER COLUMN external_reference SET NOT NULL;
ALTER TABLE invoices RENAME COLUMN total_cents TO amount_cents;

CREATE INDEX idx_orders_customer_id ON orders(customer_id);
CREATE INDEX CONCURRENTLY idx_invoices_created_at ON invoices(created_at);

COMMIT;
