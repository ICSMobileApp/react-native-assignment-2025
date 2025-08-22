**React Native Developer Assessment**

**Introduction**  
The purpose of this assignment is to evaluate your familiarity with React Native, mobile development best practices, and to showcase your approach to clean, reusable, and maintainable code. This will also help us understand your sense of design and user experience for mobile applications.

**Requirement**  
Create a simple mobile banking application.
You can use the provided BankingMockAPI (see README for API details and setup instructions) as a source of data for your application. The app should allow a user to:

1. **Authenticate** (login) using credentials.
2. **View a list of their bank accounts** (e.g., checking, savings, etc.).
3. **View transactions** related to each account (display a list of transactions for a selected account). It should include ability to:
    - search
    - sort
    - paginate between transactions
    
4. **View a list of their bank cards** (optional).

You are free to design the UI as you see fit, but the app should have at least the following screens:
- Login screen
- Accounts overview screen
- Account details/transactions screen

**Architecture**  
There are no strict requirements for architecture. Please design your application as you see fit, but focus on:
- Clean, modular, and reusable code
- Mobile development best practices
- State management (your choice: Context, Redux, Redux-Toolkit etc.)
- Clear separation of concerns

**Notes**
- The main technology for this assessment is **React Native**. You may use Expo or bare React Native CLI.
- Use TypeScript for type safety.
- The application should provide a good user experience on both iOS and Android.
- Please include a **README** file that explains your architectural decisions (e.g., why you chose a specific state management solution), instructions on how to run your solution, and details about the NodeJS and NPM/Yarn versions used.
- Please include **unit tests** for at least some key components/hooks/screens.
- Ensure the application runs without errors before submitting.
- The UI should be simple, intuitive, and visually appealing.

**Bonus Points**
- Refresh token before it expires to keep the user logged in
- Add pull-to-refresh or loading indicators where appropriate
- Add "infinite" scroll for transactions
- Add basic input validation and error handling for authentication.
- e2e tests
- Accessibility (voiceover, keyboard navigation, etc.)
- Setup CI/CD
- Feel free to add extra features or polish to demonstrate your skills