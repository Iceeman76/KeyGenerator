---
apply: always
---

# C# Coding Rules for AI Agent

## 🎯 Goal
Generate modern, clean, and production-ready C# code that is:
- Readable
- Maintainable
- Testable
- Idiomatic for .NET (latest LTS)

---

## 🧱 General Principles

- Do not put comments in the code
- Code should be in English
- Prefer clarity to cleverness
- Avoid defensive code such as null checks etc.
- Use "is null" instead of == null
- Use "is not null" instead of != null
- Avoid unnecessary abstractions
- Write self-explanatory code (minimize comments)
- Use expressive naming
- Follow SOLID where reasonable (not dogmatically)

---

## 🧾 Naming Conventions

- Use **PascalCase** for:
    - Classes
    - Methods
    - Properties
- Use **camelCase** for:
    - Local variables
    - Parameters
- Use **meaningful names**:
    - ❌ `x`, `data`, `obj`
    - ✅ `customer`, `orderItems`, `totalPrice`

---

## 🧩 Code Style

- Use **file-scoped namespaces**
- Namespaces should correspond to the file location
- If-statements should always use brackets
- If-statements should always have an empty line above it if it is not the first line in the block
- For-loops should always use brackets
- For-loops should always have an empty line above it if it is not the first line in the block
- Return statements should always have an empty line above it if it is not the first line in the block
- Records should be sealed by default
- Classes should be sealed by default if they can't be static
- Prefer **records** for immutable data
- Prefer **init-only setters** where possible
- Use **expression-bodied members** when it improves readability
- Keep methods small and focused
- Use 'var' instead of the type if possible

```csharp
public record CustomerDto(string Id, string Name);
