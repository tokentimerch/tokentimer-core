# Retirement, approval and dispatch races

`retirement-approval-api` exercises public renewal approval against operator retirement with real PostgreSQL and authenticated registered-agent claims. Complete linked agent-local renewal profiles/key mode are explicitly seeded prerequisites. Public OpenSSL certificate imports create identities; public endpoints create every job, approval and retirement. No job, observation, expiry or claim timestamp is seeded.

Seven mandatory scenarios cover an active signed-dispatch positive control, retirement before approval, retirement after approval, three concurrent approval/revocation pairs, three concurrent approval/decommission pairs, repeated dispatch fencing, and owned cleanup.

The active positive control first creates a real renewal awaiting approval. An independent workspace manager approves it, a registered protocol client receives the actual signed dispatch, and the suite independently verifies its signature and persisted attempt. The protocol client reports a deliberate failure to close that control without claiming any host execution or certificate failure.

Retiring before approval cancels the job and makes approval return HTTP409. Retiring an already approved pending job also cancels it. Concurrent requests may resolve in either approval order: the invariant is that the identity and token remain terminal, one retirement audit remains, the retired job never reaches an actual claim, its attempt count remains zero, and it produces no certificate evidence. Repeated real claim polls establish the dispatch fence. This is concurrent public traffic, not a deterministic forced database-lock interleaving test.

Focused local execution passed all seven scenarios, including cleanup. It found no new production defect. The suite verifies server admission and claim fencing; it does not launch an installed agent, contact a CA, mutate a native certificate store or qualify a hosted release. Reports bind the primary test and fixture/retirement/dispatch source fingerprints. The fixture cleanup removes only its own users/workspaces and temporary private certificate files.
