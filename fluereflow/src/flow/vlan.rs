/// The VLAN tags a frame arrived carrying, outermost first.
///
/// Part of flow identity for the same reason a tunnel is: a VLAN is a separate
/// broadcast domain, and separate domains routinely use the same addresses.
/// Without the tags, two segments' traffic would share one record.
///
/// Fixed size so the flow key stays `Copy`. Two tags cover an access port and
/// QinQ, which is what real networks use; a deeper stack is identified by its
/// outer two, so frames differing only below that are treated as one segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Default)]
pub struct VlanTags {
    /// How many of `tags` are meaningful. Zero means the frame was untagged.
    count: u8,
    tags: [u16; MAX_TAGS],
}

const MAX_TAGS: usize = 2;

impl VlanTags {
    /// Take the outermost tags from a frame's stack.
    pub fn from_stack(stack: &[u16]) -> Self {
        let mut tags = [0; MAX_TAGS];
        let count = stack.len().min(MAX_TAGS);
        tags[..count].copy_from_slice(&stack[..count]);

        VlanTags {
            count: count as u8,
            tags,
        }
    }

    /// Whether the frame carried any tag at all.
    pub fn is_tagged(&self) -> bool {
        self.count > 0
    }

    /// The tags, outermost first.
    pub fn tags(&self) -> &[u16] {
        &self.tags[..self.count as usize]
    }
}

#[cfg(test)]
mod tests {
    use super::VlanTags;

    #[test]
    fn an_untagged_frame_carries_nothing() {
        let tags = VlanTags::from_stack(&[]);
        assert!(!tags.is_tagged());
        assert!(tags.tags().is_empty());
        assert_eq!(tags, VlanTags::default());
    }

    #[test]
    fn tags_are_kept_outermost_first() {
        let tags = VlanTags::from_stack(&[10, 20]);
        assert!(tags.is_tagged());
        assert_eq!(tags.tags(), [10, 20]);
    }

    #[test]
    fn different_segments_are_different_tags() {
        assert_ne!(VlanTags::from_stack(&[100]), VlanTags::from_stack(&[200]));
        assert_ne!(VlanTags::from_stack(&[100]), VlanTags::from_stack(&[]));
        assert_ne!(
            VlanTags::from_stack(&[10, 20]),
            VlanTags::from_stack(&[10, 30])
        );
    }

    /// A one-tag frame must not compare equal to a two-tag frame whose outer
    /// tag matches, or QinQ traffic would merge with untagged-inner traffic.
    #[test]
    fn stack_depth_is_part_of_the_identity() {
        assert_ne!(VlanTags::from_stack(&[10]), VlanTags::from_stack(&[10, 0]));
    }

    #[test]
    fn a_deeper_stack_is_identified_by_its_outer_tags() {
        let tags = VlanTags::from_stack(&[1, 2, 3, 4]);
        assert_eq!(tags.tags(), [1, 2]);
    }
}
