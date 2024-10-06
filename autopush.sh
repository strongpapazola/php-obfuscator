#!/bin/bash
git add .
git commit -m "autopush"
git pull
# save credential
git config credential.helper store
git push 
