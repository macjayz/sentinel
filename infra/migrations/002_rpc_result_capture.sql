-- Phase 1: RPC result capture.
--
-- The detectors in docs/detectors.md all need to answer questions about what a provider
-- actually returned, not just whether the call errored. These columns carry the captured
-- result metadata. The result itself is never stored, only a normalized hash of it.

alter table api_events
  add column if not exists evm_block_tag text,
  add column if not exists evm_block_number bigint,
  add column if not exists evm_block_hash text,
  add column if not exists evm_result_hash text,
  add column if not exists evm_result_shape text,
  add column if not exists evm_result_count int,
  add column if not exists evm_throttled boolean,
  add column if not exists evm_rpc_error_code int,
  add column if not exists evm_rpc_error_message text,
  -- Hash of the endpoint URL. The URL is never stored: it embeds the provider API key.
  add column if not exists evm_endpoint_hash text,
  add column if not exists evm_cost_units int,
  add column if not exists evm_shadow_of_trace_id text;

-- D1 (stale head): latest observed head per endpoint per chain.
create index if not exists api_events_evm_head_idx
  on api_events(project_id, evm_chain_id, evm_endpoint_hash, timestamp desc)
  where kind = 'evm_rpc';

-- D2/D4 (disagreement, reorg lag): responses to compare at a given height.
create index if not exists api_events_evm_block_idx
  on api_events(project_id, evm_chain_id, evm_block_number)
  where kind = 'evm_rpc' and evm_block_number is not null;

-- D3 (silent failure): non-value shapes are the ones worth scanning for.
create index if not exists api_events_evm_result_shape_idx
  on api_events(project_id, evm_result_shape, timestamp desc)
  where kind = 'evm_rpc' and evm_result_shape is distinct from 'value';

-- D6 (duplicate calls): identical method at the same height inside one block.
create index if not exists api_events_evm_duplicate_idx
  on api_events(project_id, evm_rpc_method, evm_block_number, evm_result_hash)
  where kind = 'evm_rpc' and evm_block_number is not null;

-- D2 (shadow correlation): join a verification call back to the call it shadows.
create index if not exists api_events_evm_shadow_idx
  on api_events(evm_shadow_of_trace_id)
  where evm_shadow_of_trace_id is not null;

-- D5 (throttling as success): throttle rate and result degradation per endpoint.
create index if not exists api_events_evm_throttle_idx
  on api_events(project_id, evm_endpoint_hash, timestamp desc)
  where kind = 'evm_rpc';
