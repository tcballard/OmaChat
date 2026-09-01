use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

const ID_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentLoopPolicy {
    max_active_roots: usize,
    max_events_per_root: usize,
    max_hops: usize,
    max_children_per_event: usize,
    max_distinct_agents: usize,
}

impl AgentLoopPolicy {
    pub fn new(
        max_active_roots: usize,
        max_events_per_root: usize,
        max_hops: usize,
        max_children_per_event: usize,
        max_distinct_agents: usize,
    ) -> Result<Self, AgentLoopError> {
        if max_active_roots == 0
            || max_events_per_root < 2
            || max_hops == 0
            || max_children_per_event == 0
            || max_distinct_agents == 0
            || max_hops >= max_events_per_root
            || max_distinct_agents >= max_events_per_root
        {
            return Err(AgentLoopError::InvalidPolicy);
        }
        Ok(Self {
            max_active_roots,
            max_events_per_root,
            max_hops,
            max_children_per_event,
            max_distinct_agents,
        })
    }
}

impl Default for AgentLoopPolicy {
    fn default() -> Self {
        Self::new(128, 256, 8, 8, 32).expect("default agent loop policy is valid")
    }
}

#[derive(Debug)]
pub struct AgentLoopGuard {
    policy: AgentLoopPolicy,
    roots: BTreeMap<[u8; ID_BYTES], RootExecution>,
    event_roots: BTreeMap<[u8; ID_BYTES], [u8; ID_BYTES]>,
}

impl AgentLoopGuard {
    pub fn new(policy: AgentLoopPolicy) -> Self {
        Self {
            policy,
            roots: BTreeMap::new(),
            event_roots: BTreeMap::new(),
        }
    }

    pub fn active_roots(&self) -> usize {
        self.roots.len()
    }

    pub fn start_root(&mut self, root_event_id: [u8; ID_BYTES]) -> Result<(), AgentLoopError> {
        validate_id(&root_event_id)?;
        if self.event_roots.contains_key(&root_event_id) {
            return Err(AgentLoopError::EventAlreadyTracked);
        }
        if self.roots.len() >= self.policy.max_active_roots {
            return Err(AgentLoopError::ActiveRootLimit);
        }
        let mut nodes = BTreeMap::new();
        nodes.insert(
            root_event_id,
            ExecutionNode {
                parent_event_id: None,
                agent_public_key: None,
                depth: 0,
                children: 0,
            },
        );
        self.roots.insert(
            root_event_id,
            RootExecution {
                nodes,
                distinct_agents: BTreeSet::new(),
            },
        );
        self.event_roots.insert(root_event_id, root_event_id);
        Ok(())
    }

    pub fn record_agent_output(
        &mut self,
        root_event_id: &[u8; ID_BYTES],
        parent_event_id: &[u8; ID_BYTES],
        agent_public_key: [u8; ID_BYTES],
        output_event_id: [u8; ID_BYTES],
    ) -> Result<AgentExecutionObservation, AgentLoopError> {
        validate_id(root_event_id)?;
        validate_id(parent_event_id)?;
        validate_id(&agent_public_key)?;
        validate_id(&output_event_id)?;
        if self.event_roots.contains_key(&output_event_id) {
            return Err(AgentLoopError::EventAlreadyTracked);
        }

        let (depth, is_new_agent) = {
            let root = self
                .roots
                .get(root_event_id)
                .ok_or(AgentLoopError::UnknownRoot)?;
            if root.nodes.len() >= self.policy.max_events_per_root {
                return Err(AgentLoopError::EventLimit);
            }
            let parent = root
                .nodes
                .get(parent_event_id)
                .ok_or(AgentLoopError::UnknownParent)?;
            if parent.children >= self.policy.max_children_per_event {
                return Err(AgentLoopError::FanoutLimit);
            }
            let depth = parent
                .depth
                .checked_add(1)
                .ok_or(AgentLoopError::HopLimit)?;
            if depth > self.policy.max_hops {
                return Err(AgentLoopError::HopLimit);
            }

            let mut cursor = Some(*parent_event_id);
            while let Some(event_id) = cursor {
                let node = root
                    .nodes
                    .get(&event_id)
                    .expect("causal parent was validated on insertion");
                if node.agent_public_key == Some(agent_public_key) {
                    return Err(AgentLoopError::AgentCycle);
                }
                cursor = node.parent_event_id;
            }
            let is_new_agent = !root.distinct_agents.contains(&agent_public_key);
            if is_new_agent && root.distinct_agents.len() >= self.policy.max_distinct_agents {
                return Err(AgentLoopError::DistinctAgentLimit);
            }
            (depth, is_new_agent)
        };

        let root = self
            .roots
            .get_mut(root_event_id)
            .expect("root was validated before mutation");
        root.nodes
            .get_mut(parent_event_id)
            .expect("parent was validated before mutation")
            .children += 1;
        root.nodes.insert(
            output_event_id,
            ExecutionNode {
                parent_event_id: Some(*parent_event_id),
                agent_public_key: Some(agent_public_key),
                depth,
                children: 0,
            },
        );
        if is_new_agent {
            root.distinct_agents.insert(agent_public_key);
        }
        self.event_roots.insert(output_event_id, *root_event_id);
        Ok(AgentExecutionObservation { depth })
    }

    pub fn trace_agents(
        &self,
        root_event_id: &[u8; ID_BYTES],
        event_id: &[u8; ID_BYTES],
    ) -> Result<Vec<[u8; ID_BYTES]>, AgentLoopError> {
        let root = self
            .roots
            .get(root_event_id)
            .ok_or(AgentLoopError::UnknownRoot)?;
        let mut cursor = Some(*event_id);
        let mut agents = Vec::new();
        while let Some(current) = cursor {
            let node = root
                .nodes
                .get(&current)
                .ok_or(AgentLoopError::UnknownParent)?;
            if let Some(agent) = node.agent_public_key {
                agents.push(agent);
            }
            cursor = node.parent_event_id;
        }
        agents.reverse();
        Ok(agents)
    }

    pub fn complete_root(&mut self, root_event_id: &[u8; ID_BYTES]) -> bool {
        let Some(root) = self.roots.remove(root_event_id) else {
            return false;
        };
        for event_id in root.nodes.keys() {
            self.event_roots.remove(event_id);
        }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentExecutionObservation {
    depth: usize,
}

impl AgentExecutionObservation {
    pub fn depth(&self) -> usize {
        self.depth
    }
}

#[derive(Debug)]
struct RootExecution {
    nodes: BTreeMap<[u8; ID_BYTES], ExecutionNode>,
    distinct_agents: BTreeSet<[u8; ID_BYTES]>,
}

#[derive(Clone, Copy, Debug)]
struct ExecutionNode {
    parent_event_id: Option<[u8; ID_BYTES]>,
    agent_public_key: Option<[u8; ID_BYTES]>,
    depth: usize,
    children: usize,
}

fn validate_id(value: &[u8; ID_BYTES]) -> Result<(), AgentLoopError> {
    if value == &[0; ID_BYTES] {
        Err(AgentLoopError::ZeroIdentifier)
    } else {
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentLoopError {
    InvalidPolicy,
    ZeroIdentifier,
    ActiveRootLimit,
    UnknownRoot,
    UnknownParent,
    EventAlreadyTracked,
    EventLimit,
    HopLimit,
    FanoutLimit,
    DistinctAgentLimit,
    AgentCycle,
}

impl fmt::Display for AgentLoopError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPolicy => "invalid agent loop policy",
            Self::ZeroIdentifier => "agent loop identifiers must be non-zero",
            Self::ActiveRootLimit => "too many active agent execution roots",
            Self::UnknownRoot => "unknown agent execution root",
            Self::UnknownParent => "unknown causal parent event",
            Self::EventAlreadyTracked => "event is already tracked by an execution root",
            Self::EventLimit => "agent execution root exceeded its event budget",
            Self::HopLimit => "agent execution exceeded its hop budget",
            Self::FanoutLimit => "agent event exceeded its child fan-out budget",
            Self::DistinctAgentLimit => "agent execution exceeded its distinct-agent budget",
            Self::AgentCycle => "agent execution would repeat an agent in its causal ancestry",
        })
    }
}

impl Error for AgentLoopError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_agent_cycle_is_rejected_without_mutating_the_trace() {
        let mut guard = AgentLoopGuard::new(AgentLoopPolicy::default());
        guard.start_root([1; 32]).expect("root");
        guard
            .record_agent_output(&[1; 32], &[1; 32], [10; 32], [2; 32])
            .expect("agent A");
        guard
            .record_agent_output(&[1; 32], &[2; 32], [11; 32], [3; 32])
            .expect("agent B");
        guard
            .record_agent_output(&[1; 32], &[3; 32], [12; 32], [4; 32])
            .expect("agent C");
        assert_eq!(
            guard.record_agent_output(&[1; 32], &[4; 32], [10; 32], [5; 32]),
            Err(AgentLoopError::AgentCycle)
        );
        assert_eq!(
            guard.trace_agents(&[1; 32], &[4; 32]).expect("trace"),
            vec![[10; 32], [11; 32], [12; 32]]
        );
        assert_eq!(
            guard.trace_agents(&[1; 32], &[5; 32]),
            Err(AgentLoopError::UnknownParent)
        );
    }

    #[test]
    fn hop_fanout_and_active_root_budgets_are_enforced() {
        let policy = AgentLoopPolicy::new(1, 5, 2, 1, 2).expect("policy");
        let mut guard = AgentLoopGuard::new(policy);
        guard.start_root([1; 32]).expect("root");
        guard
            .record_agent_output(&[1; 32], &[1; 32], [10; 32], [2; 32])
            .expect("first hop");
        assert_eq!(
            guard.record_agent_output(&[1; 32], &[1; 32], [11; 32], [3; 32]),
            Err(AgentLoopError::FanoutLimit)
        );
        guard
            .record_agent_output(&[1; 32], &[2; 32], [11; 32], [3; 32])
            .expect("second hop");
        assert_eq!(
            guard.record_agent_output(&[1; 32], &[3; 32], [12; 32], [4; 32]),
            Err(AgentLoopError::HopLimit)
        );
        assert_eq!(
            guard.start_root([9; 32]),
            Err(AgentLoopError::ActiveRootLimit)
        );
    }

    #[test]
    fn event_and_distinct_agent_budgets_are_enforced_independently() {
        let mut distinct = AgentLoopGuard::new(
            AgentLoopPolicy::new(1, 6, 4, 2, 2).expect("distinct-agent policy"),
        );
        distinct.start_root([1; 32]).expect("root");
        distinct
            .record_agent_output(&[1; 32], &[1; 32], [10; 32], [2; 32])
            .expect("first agent");
        distinct
            .record_agent_output(&[1; 32], &[2; 32], [11; 32], [3; 32])
            .expect("second agent");
        assert_eq!(
            distinct.record_agent_output(&[1; 32], &[3; 32], [12; 32], [4; 32]),
            Err(AgentLoopError::DistinctAgentLimit)
        );

        let mut events =
            AgentLoopGuard::new(AgentLoopPolicy::new(1, 3, 2, 2, 2).expect("event policy"));
        events.start_root([5; 32]).expect("root");
        events
            .record_agent_output(&[5; 32], &[5; 32], [20; 32], [6; 32])
            .expect("first event");
        events
            .record_agent_output(&[5; 32], &[6; 32], [21; 32], [7; 32])
            .expect("second event");
        assert_eq!(
            events.record_agent_output(&[5; 32], &[7; 32], [22; 32], [8; 32]),
            Err(AgentLoopError::EventLimit)
        );
    }

    #[test]
    fn duplicate_events_cannot_cross_roots_and_completion_releases_capacity() {
        let policy = AgentLoopPolicy::new(2, 8, 4, 2, 4).expect("policy");
        let mut guard = AgentLoopGuard::new(policy);
        guard.start_root([1; 32]).expect("first root");
        guard.start_root([2; 32]).expect("second root");
        guard
            .record_agent_output(&[1; 32], &[1; 32], [10; 32], [3; 32])
            .expect("first output");
        assert_eq!(
            guard.record_agent_output(&[2; 32], &[2; 32], [11; 32], [3; 32]),
            Err(AgentLoopError::EventAlreadyTracked)
        );
        assert!(guard.complete_root(&[1; 32]));
        assert!(!guard.complete_root(&[1; 32]));
        guard
            .record_agent_output(&[2; 32], &[2; 32], [11; 32], [3; 32])
            .expect("event ID released with completed root");
        guard.start_root([9; 32]).expect("capacity released");
    }
}
