# Deployment

Compose topology, Dockerfiles, and examples land in M2 (dev topology) and M8
(release images). Release files must pin the 389 DS image by digest, never a
floating tag.
