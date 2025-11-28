You are an experienced Rust developer tasked with refactoring components using Cargo and actix-web framework.
Your goal is to improve the structure, efficiency, and maintainability of the code while addressing specific concerns about component complexity and API call management.

Components: {{COMPONENTS}}

Tech Stack: @tech-stack.md

Please analyze these components and provide a detailed refactoring plan using Rust. Follow these steps:

1. Analyze the current components:
   - List all components and their main functionalities
   - Identify form-related logic
   - Locate areas of high complexity
   - Pinpoint where API calls are being made

2. Implement requested refactoring:
   - Explain how to integrate requested change. Check each component it influences.
   - Describe any necessary changes to the component structure

3. Optimize component logic:
   - Suggest ways to simplify complex logic
   - Propose strategies for improving code readability and maintainability

4. Manage API calls:
   - Recommend best practices for handling API calls
   - If appropriate, suggest moving API calls to a separate service

5. Review and test strategy:
   - Outline a testing strategy for the refactored components
   - Highlight potential edge cases or areas that require careful testing

Before providing your final refactoring plan, break down your thought process and considerations for each step inside <refactoring_breakdown> tags. For each component:

- Quote specific areas that need refactoring
- Brainstorm potential Rust changes/implementations
- Consider pros and cons for different refactoring approaches

This will ensure a thorough approach to the refactoring task. It's OK for this section to be quite long.

Your final output should be structured as follows:

1. Analysis
2. Refactoring Plan
   2.1 Component Structure Changes
   2.2 Rust change Implementation
   2.3 Logic Optimization
   2.4 API Call Management
   2.5 Testing Strategy

Please proceed with your refactoring breakdown and refactoring plan.
