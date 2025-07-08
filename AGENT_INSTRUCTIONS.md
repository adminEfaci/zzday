# Agent Instructions and Commands

## How to Instruct Claude Code for Multi-Agent Analysis

### 1. Initial Setup Commands

```bash
# First, commit the strategy documents
"Commit the Git strategy documents to master"

# Then create the branch structure
"Create all analysis branches as defined in GIT_STRATEGY.md"

# Initialize agent directories
"Set up the documentation structure for all agents"
```

### 2. Agent Assignment Commands

#### Assign Claude as Architecture Agent:
```
"You are now the Architecture Agent. Your branch is analysis/architecture. 
Your focus is on analyzing system architecture, DDD boundaries, and hexagonal architecture compliance.
Begin by checking out your branch and creating your initial analysis structure."
```

#### Assign Claude as Domain Agent:
```
"You are now the Domain Agent. Your branch is analysis/domain.
Your focus is on domain models, entities, value objects, and aggregates.
Begin by checking out your branch and creating your initial analysis structure."
```

#### Assign Claude as Service Agent:
```
"You are now the Service Agent. Your branch is analysis/services.
Your focus is on application services, command/query handlers, and use cases.
Begin by checking out your branch and creating your initial analysis structure."
```

#### Assign Claude as Infrastructure Agent:
```
"You are now the Infrastructure Agent. Your branch is analysis/infrastructure.
Your focus is on infrastructure implementations, repositories, and external integrations.
Begin by checking out your branch and creating your initial analysis structure."
```

#### Assign Claude as Interface Agent:
```
"You are now the Interface Agent. Your branch is analysis/interfaces.
Your focus is on contracts, ports, adapters, and API boundaries.
Begin by checking out your branch and creating your initial analysis structure."
```

### 3. Analysis Task Commands

#### Starting Analysis:
```
"As [Agent Role], analyze the following file: backend/app/modules/identity/domain/entities/user.py
Follow the structured analysis template and create your report in docs/analysis/[agent-area]/identity_domain_analysis.md"
```

#### Continuing Analysis:
```
"Continue your analysis as [Agent Role] with the next file in the identity module.
Update your existing analysis document with the new findings."
```

#### Cross-Reference Analysis:
```
"As [Agent Role], cross-reference your findings with the contracts in 
backend/app/modules/identity/domain/interfaces/. Document any discrepancies."
```

### 4. Git Workflow Commands

#### Daily Work Commit:
```
"Commit your current analysis work with an appropriate message following our convention.
Push to your agent branch."
```

#### Request Coordination Merge:
```
"Your daily analysis is complete. Prepare your work for coordination merge.
Create a summary of today's findings."
```

#### Switch Agent Roles:
```
"Save and commit your current work as [Current Agent].
Switch to [New Agent] role and checkout the appropriate branch.
Begin analysis of [specific area]."
```

### 5. Coordination Commands

#### Daily Consolidation:
```
"Act as the Coordination Agent. Merge all agent branches into analysis/coordination.
Resolve any conflicts according to our priority matrix.
Generate the daily consolidation report."
```

#### Weekly Review:
```
"Create this week's review branch. 
Consolidate all agent findings into the weekly report.
Identify critical issues and action items."
```

#### Master Integration:
```
"The weekly review is approved. 
Merge the review branch into master following our integration process.
Tag the release appropriately."
```

### 6. Specific Analysis Commands

#### File Analysis:
```
"Analyze backend/app/modules/[module]/[layer]/[file].py

Provide:
1. File purpose and responsibility
2. Classes and their SRP compliance  
3. Top 3 methods per class with signatures
4. Import boundary verification
5. Real-world workflow implications
6. Any violations or issues found"
```

#### Module Analysis:
```
"Perform complete analysis of the [module name] module.
Cover all layers: domain, application, infrastructure, presentation.
Document the module's adherence to DDD principles."
```

#### Cross-Module Analysis:
```
"Analyze cross-module dependencies between [module1] and [module2].
Identify any boundary violations or tight coupling.
Suggest refactoring if needed."
```

### 7. Progress Tracking Commands

#### Update Progress:
```
"Update the tracking log with current analysis progress.
Mark completed items and add any new discoveries to the backlog."
```

#### Status Report:
```
"Generate a status report showing:
- Files analyzed today
- Findings summary  
- Blocked items
- Tomorrow's planned work"
```

#### Metrics Report:
```
"Calculate and report:
- Total files analyzed
- Violations found by category
- Coverage percentage by module
- Estimated completion timeline"
```

### 8. Quality Assurance Commands

#### Peer Review:
```
"As [Agent], review the analysis done by [Other Agent] on [specific file/module].
Provide feedback and identify any missed issues."
```

#### Consistency Check:
```
"Cross-check analyses from all agents for the [module] module.
Identify any conflicting interpretations or findings."
```

#### Validation:
```
"Validate that all analysis documents follow the structured template.
Fix any formatting or content structure issues."
```

### 9. Advanced Workflow Commands

#### Parallel Analysis:
```
"Split into parallel analysis mode:
1. As Architecture Agent, analyze module structure
2. As Domain Agent, analyze domain models  
3. As Service Agent, analyze use cases
Maintain separate documentation for each perspective."
```

#### Deep Dive:
```
"Perform deep dive analysis on [specific concern]:
- Trace the complete flow
- Document all touchpoints
- Identify potential issues
- Suggest improvements"
```

#### Hotfix Identification:
```
"Critical issue found in [location].
Create hotfix branch and document:
- Issue description
- Impact analysis
- Recommended fix
- Testing requirements"
```

### 10. Communication Commands

#### Ask for Clarification:
```
"As [Agent], I need clarification on [specific issue].
Document the question in the analysis notes.
Proceed with assumptions clearly stated."
```

#### Report Blocking Issue:
```
"Document blocking issue:
- What is blocked
- Why it's blocked  
- What's needed to unblock
- Impact on timeline"
```

#### Escalate Finding:
```
"Escalate critical finding to hotfix process:
- Create hotfix branch
- Document severity and impact
- Propose immediate action"
```

## Example Complete Workflow

### Day 1: Setup and Initial Analysis
```bash
# 1. Initialize as Architecture Agent
"You are the Architecture Agent. Check out your branch and analyze the identity module's overall architecture."

# 2. Perform analysis
"Analyze backend/app/modules/identity/ structure. Focus on layer separation and DDD boundaries."

# 3. Commit work
"Commit your architecture analysis for the identity module."

# 4. Switch to Domain Agent
"Switch to Domain Agent role. Analyze identity module's domain entities."

# 5. End of day
"As Coordination Agent, merge today's work from all agents."
```

### Day 2: Deep Dive
```bash
# 1. Continue as assigned agent
"As [Agent], continue analysis with the audit module."

# 2. Cross-reference
"Cross-reference audit module with identity module interfaces."

# 3. Document findings
"Document integration points and contract compliance."
```

### Week End: Review
```bash
# 1. Create review
"Create this week's review branch and consolidate all findings."

# 2. Generate report
"Generate comprehensive weekly report with all agent findings."

# 3. Prepare for merge
"Prepare the review for master integration."
```

## Command Response Patterns

Claude will respond to these commands by:

1. **Confirming Role**: "Acknowledged. Acting as [Agent Role] on branch [branch]."
2. **Starting Task**: "Beginning analysis of [target]. Creating documentation at [path]."
3. **Completing Task**: "Analysis complete. Findings documented. Ready for next task."
4. **Requesting Clarification**: "Need clarification on [issue] before proceeding."
5. **Reporting Status**: "Current progress: X files analyzed, Y findings documented."

## Best Practices

1. **Be Specific**: Always specify which agent role and which files/modules to analyze
2. **Maintain Context**: Reference previous analyses when requesting continued work  
3. **Clear Transitions**: Explicitly state when switching between agent roles
4. **Track Progress**: Regularly request progress updates and tracking log updates
5. **Document Everything**: Ensure all findings are properly documented before moving on

---
*Use these commands to orchestrate the multi-agent analysis workflow effectively.*