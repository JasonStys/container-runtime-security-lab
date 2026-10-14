-- Jason Stys: pseudonymized detection evidence with parameterized inserts; no raw audit objects/actors.
-- BEGIN CODE MAP (generated; python scripts/code_map.py)
-- SQL object: review — line 22
-- column: as_of — line 22
-- column: complete — line 22
-- column: duplicates — line 22
-- column: received — line 22
-- column: unique_count — line 22
-- SQL object: alert — line 23
-- column: event — line 23
-- column: namespace — line 23
-- column: priority — line 23
-- column: rule — line 23
-- column: source — line 23
-- column: subject — line 23
-- column: time — line 23
-- SQL object: gap — line 24
-- column: reason — line 24
-- column: source — line 24
-- SQL object: alert_source_rule — line 25
-- END CODE MAP
CREATE TABLE review(as_of TEXT NOT NULL, received INTEGER NOT NULL, unique_count INTEGER NOT NULL, duplicates INTEGER NOT NULL, complete INTEGER NOT NULL CHECK(complete IN(0,1)));
CREATE TABLE alert(event TEXT NOT NULL, rule TEXT NOT NULL, source TEXT NOT NULL, priority TEXT NOT NULL, namespace TEXT NOT NULL, subject TEXT NOT NULL, time TEXT NOT NULL, PRIMARY KEY(event,rule,source));
CREATE TABLE gap(source TEXT NOT NULL, reason TEXT NOT NULL);
CREATE INDEX alert_source_rule ON alert(source,rule);
