-- Support ordered, batched deletion of old click events.
CREATE INDEX IF NOT EXISTS idx_click_events_clicked_at_id
    ON click_events (clicked_at, id);
