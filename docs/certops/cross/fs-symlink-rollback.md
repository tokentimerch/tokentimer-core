# Filesystem permission, symlink, and rollback

A symlink or junction whose target leaves the owned root fails before a read or write. The walker stops on the link and does not follow it. Permission denied fails closed. Rollback writes the previous bytes back to a regular file inside the owned root.

`followedSymlink` stays false. A missing filesystem lab fails closed, and `hostCapabilityAbsentIsPass` is false.

The catalog rows `deploy.path-containment`, `deploy.atomic-backups`, `deploy.leaf-chain-key`, and `linux-install.state-permissions` are annotated only. This file does not promote them.
