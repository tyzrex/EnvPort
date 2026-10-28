# ADR-0005: explicit scan roots bound project discovery

Accepted 2026-10-28 after concurrency/history regression tests exposed an ancestor-marker edge case.

ProjectRoot must stop at the explicit scan root, even if its parent or a filesystem ancestor contains .git metadata. Git identity resolution requires a real nonsymlink .git marker at the identified project root rather than inheriting an ancestor's repository through Git's directory traversal. This prevents enrollment from silently broadening an authorized root and associating an incorrect path/identity. Nested repositories and worktree markers remain supported inside the chosen root.

If only a repository subdirectory is selected, it is not silently treated as the full parent checkout. Select the actual checkout root for Git identity enrollment or explicitly use local UUID enrollment. Dedicated ancestor-marker and subdirectory-identity regression tests guard the boundary.
